import os
import sys
import types
import random
import asyncio
from datetime import datetime, timedelta, timezone
import socks
from cryptography.fernet import Fernet
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import (
    FloodWaitError,
    ChatWriteForbiddenError,
    UserBannedInChannelError,
    SlowModeWaitError,
    ChannelPrivateError,
    ChatAdminRequiredError,
    PeerFloodError,
    AuthKeyDuplicatedError,
)

from messages_pool import WATER_MESSAGES_POOL

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WORKFLOW_YML_PATH = os.path.join(BASE_DIR, ".github", "workflows", "tg_auto_send.yml")
PLAIN_CONFIG_PATH = os.path.join(BASE_DIR, "config.py")
ENC_CONFIG_PATH = os.path.join(BASE_DIR, "config.enc")
LOCAL_KEY_PATH = os.path.join(BASE_DIR, ".secret_key")

LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
RUN_LOG_FILE = os.path.join(LOG_DIR, "latest_run.log")
HISTORY_LOG_FILE = os.path.join(LOG_DIR, "run_history.log")

# 是否处于 GitHub Actions 云端公开环境（云端环境强制开启 100% 隐私脱敏日志，绝不输出任何群名、群ID、账号名）
IS_CLOUD = os.getenv("GITHUB_ACTIONS") == "true"

# 北京时区 (UTC+8)
BJ_TZ = timezone(timedelta(hours=8))

# 单个 GitHub 容器最大持续驻留接力时长（秒）：设为 5.4 小时 (19440 秒)
MAX_CONTAINER_HOLD_SECONDS = int(5.4 * 3600)


def bj_now_str() -> str:
    return datetime.now(BJ_TZ).strftime("%Y-%m-%d %H:%M:%S")


def log_info(msg: str):
    """同时输出到控制台和本地日志（云端模式下控制台输出已全面脱敏）"""
    line = f"[{bj_now_str()}] {msg}"
    print(line, flush=True)
    if not IS_CLOUD:
        try:
            with open(RUN_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            with open(HISTORY_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


def get_or_create_secret_key() -> bytes:
    """获取加密主密钥（云端从 GitHub Secrets 环境变量读取，本地从 .secret_key 读取或自动生成）"""
    env_key = os.getenv("CONFIG_SECRET_KEY", "").strip()
    if env_key:
        return env_key.encode("ascii")
    if os.path.exists(LOCAL_KEY_PATH):
        with open(LOCAL_KEY_PATH, "rb") as f:
            return f.read().strip()
    new_key = Fernet.generate_key()
    with open(LOCAL_KEY_PATH, "wb") as f:
        f.write(new_key)
    return new_key


def encrypt_local_config_to_enc() -> bool:
    """将本地明文 config.py 使用 AES-128-CBC + HMAC-SHA256 (Fernet) 全量加密生成 config.enc"""
    if not os.path.exists(PLAIN_CONFIG_PATH):
        return False
    key = get_or_create_secret_key()
    cipher = Fernet(key)
    with open(PLAIN_CONFIG_PATH, "rb") as f:
        plain_bytes = f.read()
    enc_bytes = cipher.encrypt(plain_bytes)
    with open(ENC_CONFIG_PATH, "wb") as f:
        f.write(enc_bytes)
    return True


def load_config_module():
    """
    安全加载配置模块：
    - 本地存在明文 config.py 时：直接读取并自动同步加密生成最新的 config.enc
    - 云端公开仓库（仅有 config.enc）时：使用 GitHub Secrets 中的 CONFIG_SECRET_KEY 在【纯内存】中解密加载，绝不落盘任何明文！
    """
    if os.path.exists(PLAIN_CONFIG_PATH):
        encrypt_local_config_to_enc()
        import config as local_cfg
        return local_cfg

    if not os.path.exists(ENC_CONFIG_PATH):
        raise RuntimeError("未找到加密配置文件 config.enc！")

    env_key = os.getenv("CONFIG_SECRET_KEY", "").strip()
    if not env_key:
        raise RuntimeError("未检测到环境变量 CONFIG_SECRET_KEY，无法解密 config.enc！")

    cipher = Fernet(env_key.encode("ascii"))
    with open(ENC_CONFIG_PATH, "rb") as f:
        enc_bytes = f.read().strip()

    decrypted_source = cipher.decrypt(enc_bytes).decode("utf-8")
    cfg_mod = types.ModuleType("config")
    exec(compile(decrypted_source, "<encrypted_config>", "exec"), cfg_mod.__dict__)
    sys.modules["config"] = cfg_mod
    return cfg_mod


config = load_config_module()


def classify_tg_error(err: Exception) -> str:
    """将 Telegram 常见发送失败异常翻译为直观的中文排查原因"""
    err_name = type(err).__name__
    if isinstance(err, asyncio.TimeoutError):
        return f"[单次网络请求超时(30秒)，已自动跳过防卡死] ({err_name})"
    if isinstance(err, SlowModeWaitError):
        return f"[群开启了慢速发言模式] 需等待 {err.seconds} 秒才能发下一条 ({err_name})"
    if isinstance(err, FloodWaitError):
        return f"[触发 TG 频率限制] 需等待 {err.seconds} 秒 ({err_name})"
    if isinstance(err, UserBannedInChannelError):
        return f"[账号在该群被禁言或限制发言] ({err_name})"
    if isinstance(err, ChatWriteForbiddenError):
        return f"[该群全员禁言或无发言权限(如未通过入群验证/被机器人禁言)] ({err_name})"
    if isinstance(err, ChannelPrivateError):
        return f"[已不在该群内或被踢出/群已解散] ({err_name})"
    if isinstance(err, ChatAdminRequiredError):
        return f"[需要管理员权限才能发言] ({err_name})"
    if isinstance(err, PeerFloodError):
        return f"[触发 TG 全局风控限制(PeerFlood)，建议暂停水群休息一天] ({err_name})"
    if isinstance(err, AuthKeyDuplicatedError):
        return f"[Session 冲突：同一时间有另一个进程正在使用该账号连接] ({err_name})"
    return f"[{err_name}]" if IS_CLOUD else f"[{err_name}] {str(err)}"


def sync_schedule_to_github_yml():
    """
    加密本地 config.py -> config.enc，并生成高频多锚点预唤醒 GitHub Actions 配置（全加密无痕版）
    """
    encrypt_local_config_to_enc()
    rounds = list(getattr(config, "DAILY_WATER_ROUNDS", getattr(config, "SCHEDULE_BEIJING_TIMES", ["12:00"])))
    cron_lines = [
        "    - cron: '15 23 * * *'  # 早间预唤醒1 (北京时间 07:15 进场，5.4h驻留直达 12:00 首轮)",
        "    - cron: '30 0 * * *'   # 早间预唤醒2 (北京时间 08:30 双保险进场，防 GitHub 漏触发)",
        "    - cron: '45 1 * * *'   # 早间预唤醒3 (北京时间 09:45 三保险进场，防 GitHub 延迟)",
        "    - cron: '0 3 * * *'    # 早间预唤醒4 (北京时间 11:00 四保险进场，确保 12:00 100% 准时)",
        "    - cron: '20 4 * * *'   # 午间预唤醒1 (北京时间 12:20 排队接力下午场)",
        "    - cron: '50 5 * * *'   # 午间预唤醒2 (北京时间 13:50 排队接力下午场)",
        "    - cron: '20 7 * * *'   # 午间预唤醒3 (北京时间 15:20 排队接力下午场)",
        "    - cron: '50 8 * * *'   # 晚间预唤醒1 (北京时间 16:50 排队接力晚间场)",
        "    - cron: '20 10 * * *'  # 晚间预唤醒2 (北京时间 18:20 排队接力晚间场)",
        "    - cron: '50 11 * * *'  # 晚间预唤醒3 (北京时间 19:50 兜底接力至 22:50 结束)",
    ]

    yml_content = f"""name: Telegram Auto Water & Signin

on:
  workflow_dispatch:
    inputs:
      mode:
        description: '执行模式: wait (按时间表精准倒计时连续跑) / now (立即发一轮)'
        required: false
        default: 'wait'

  push:
    branches:
      - main
    paths:
      - 'config.enc'
      - 'cloud_runner.py'
      - 'messages_pool.py'
      - '.github/workflows/tg_auto_send.yml'

  schedule:
{chr(10).join(cron_lines)}

concurrency:
  group: tg-userbot-runner
  cancel-in-progress: ${{{{ github.event_name != 'schedule' }}}}

jobs:
  send-messages:
    runs-on: ubuntu-latest
    timeout-minutes: 350

    steps:
      - name: 📥 检出代码仓库
        uses: actions/checkout@v4

      - name: 🐍 配置 Python 3.12 环境
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          cache: 'pip'

      - name: 📦 安装依赖库
        run: |
          pip install telethon pysocks python-socks cryptography

      - name: 🚀 启动加密多轮精准时钟引擎 (纯内存解密与无痕脱敏模式)
        env:
          CONFIG_SECRET_KEY: ${{{{ secrets.CONFIG_SECRET_KEY }}}}
          GITHUB_EVENT_NAME: ${{{{ github.event_name }}}}
          GITHUB_EVENT_SCHEDULE: ${{{{ github.event.schedule }}}}
          INPUT_MODE: ${{{{ github.event.inputs.mode }}}}
        run: |
          python cloud_runner.py
"""
    os.makedirs(os.path.dirname(WORKFLOW_YML_PATH), exist_ok=True)
    with open(WORKFLOW_YML_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(yml_content)
    log_info(f"🔒 已将 config.py 加密为 config.enc，并同步 {len(rounds)} 轮防漏预唤醒配置至 GitHub")


def get_upcoming_rounds(executed_today: set[str]) -> list[tuple[int, str, list, datetime]]:
    """
    获取未来待执行的轮次列表，按时间先后排序：
    返回 [(round_index, round_key, group_ids, target_datetime), ...]
    """
    rounds: list = list(getattr(config, "DAILY_WATER_ROUNDS", getattr(config, "SCHEDULE_BEIJING_TIMES", [])))
    batches: dict = getattr(config, "SCHEDULE_BATCHES", {})
    all_fallback: list = getattr(config, "TARGET_GROUP_IDS", [])
    now_bj = datetime.now(BJ_TZ)

    upcoming = []
    for idx, t_str in enumerate(rounds):
        parts = str(t_str).strip().split(":")
        if len(parts) >= 2:
            h, m = int(parts[0]), int(parts[1])
            target_today = now_bj.replace(hour=h, minute=m, second=0, microsecond=0)
            diff_sec = (target_today - now_bj).total_seconds()
            g_list = batches.get(t_str, all_fallback)

            # 只选取未来还未到达的轮次（不再回溯已过去的旧轮次，杜绝跨容器交接重复执行）
            today_tag = f"{target_today.strftime('%Y-%m-%d')}_{t_str}"
            if today_tag not in executed_today:
                if diff_sec > -60:
                    upcoming.append((idx, t_str, g_list, target_today))
                    continue

            # 否则排到明天的这一轮
            target_tmr = target_today + timedelta(days=1)
            upcoming.append((idx, t_str, g_list, target_tmr))

    upcoming.sort(key=lambda x: x[3])
    return upcoming


async def wait_until_exact_beijing_time(target_dt: datetime, round_num: int, total_rounds: int, round_key: str) -> None:
    """Python 内部高精度时钟倒计时，误差 < 0.1 秒"""
    now_bj = datetime.now(BJ_TZ)
    remain_sec = (target_dt - now_bj).total_seconds()

    if remain_sec <= 0:
        log_info(f"⚡ [精准时钟对齐] 当前已到达第 {round_num}/{total_rounds} 轮 [{round_key}]，立即开始发送！")
        return

    log_info(
        f"⏱️ [精准时钟锁定] 下一轮: 第 {round_num}/{total_rounds} 轮 (目标北京时间 {target_dt.strftime('%Y-%m-%d %H:%M:%S')})"
    )
    log_info(
        f"⏳ 当前北京时间: {bj_now_str()} | 距离本轮发射还有: {int(remain_sec // 60)} 分 {int(remain_sec % 60)} 秒"
    )

    last_log_min = -1
    while True:
        now_bj = datetime.now(BJ_TZ)
        remain = (target_dt - now_bj).total_seconds()
        if remain <= 0:
            break

        rem_mins = int(remain // 60)
        if rem_mins != last_log_min and (rem_mins % 10 == 0 or rem_mins in (5, 2, 1)):
            last_log_min = rem_mins
            log_info(
                f"⏳ [精准倒计时] 距离第 {round_num}/{total_rounds} 轮 ({target_dt.strftime('%H:%M:%S')}) 还有 {rem_mins} 分 {int(remain % 60)} 秒..."
            )

        if remain > 30:
            await asyncio.sleep(10.0)
        elif remain > 2:
            await asyncio.sleep(0.5)
        else:
            await asyncio.sleep(0.05)

    log_info(f"🎯 [精准卡点命中] 北京时间 {bj_now_str()} 到达第 {round_num}/{total_rounds} 轮 [{round_key}]！开始发送！")


def get_proxy():
    if IS_CLOUD:
        return None
    if getattr(config, "USE_LOCAL_PROXY", False):
        p_type = getattr(config, "PROXY_TYPE", "socks5").lower()
        host = getattr(config, "PROXY_HOST", "127.0.0.1")
        port = int(getattr(config, "PROXY_PORT", 7897))
        proxy_type = socks.SOCKS5 if p_type == "socks5" else socks.HTTP
        return (proxy_type, host, port)
    return None


def pick_single_non_repeating_message(group_id: int, water_slot_index: int) -> str:
    """
    利用【当天日期 + 群ID】作为独立随机种子，每天为每个群预先洗牌生成专属不重复语录队列：
    严格按今日未使用槽位 water_slot_index 每次只取 1 条，100% 绝不重复、绝不连发 2 条！
    """
    valid_pool = [m for m in WATER_MESSAGES_POOL if len(m) >= 8]
    if not valid_pool:
        return "今天大家聊得挺热闹啊我也来冒个泡"

    today_str = datetime.now(BJ_TZ).strftime("%Y-%m-%d")
    rng = random.Random(f"{today_str}_group_{group_id}")
    shuffled_pool = list(valid_pool)
    rng.shuffle(shuffled_pool)

    return shuffled_pool[water_slot_index % len(shuffled_pool)]


async def send_one_message(client: TelegramClient, chat_id: int, text: str):
    """发送单条消息，带 30 秒超时保护"""
    if getattr(config, "SIMULATE_TYPING", True):
        typing_duration = min(max(len(text) * 0.25, 1.5), 3.5)
        await asyncio.sleep(typing_duration)
    await asyncio.wait_for(client.send_message(chat_id, text), timeout=30.0)


async def check_today_progress(client: TelegramClient, me_id: int) -> tuple[bool, int, int, float]:
    """
    通过检查参考群今日已发消息记录，同时返回：
    1) already_signed (bool): 今天是否已经发送过 "签到"
    2) water_sent_today (int): 今天已经成功发送过多少条【不重复】的水群消息
    3) next_unused_slot_index (int): 下一个绝对未被使用过的语录槽位序号，彻底杜绝重复发送同一句话
    4) last_msg_age_sec (float): 距离上一条已发消息（含签到或水群）过去了多少秒，用于防止 40 分钟内重复触发
    """
    now_bj = datetime.now(BJ_TZ)
    today_str = now_bj.strftime("%Y-%m-%d")
    prefix_set = {m.strip() for m in getattr(config, "FIXED_PREFIX_MESSAGES", ["签到"]) if str(m).strip()}
    valid_pool = [m for m in WATER_MESSAGES_POOL if len(m) >= 8]

    probe_groups = list(getattr(config, "PROBE_GROUP_IDS", []))
    if not probe_groups:
        all_t = [int(x) for x in getattr(config, "TARGET_GROUP_IDS", []) if isinstance(x, int) or str(x).lstrip("-").isdigit()]
        signin_only = {int(x) for x in getattr(config, "SIGNIN_ONLY_GROUP_IDS", []) if isinstance(x, int) or str(x).lstrip("-").isdigit()}
        probe_groups = [g for g in all_t if g not in signin_only][:3]

    for idx_p, gid in enumerate(probe_groups):
        try:
            msgs = await asyncio.wait_for(client.get_messages(gid, from_user=me_id, limit=35), timeout=15.0)
            signed_in = False
            unique_water_texts = set()
            last_msg_age_sec = 999999.0
            for m in msgs:
                msg_dt_bj = m.date.astimezone(BJ_TZ)
                if msg_dt_bj.strftime("%Y-%m-%d") == today_str:
                    txt = (m.text or "").strip()
                    age = (now_bj - msg_dt_bj).total_seconds()
                    if age < last_msg_age_sec:
                        last_msg_age_sec = age
                    if txt in prefix_set:
                        signed_in = True
                    elif len(txt) >= 6:
                        unique_water_texts.add(txt)
            if idx_p == 0 or signed_in or unique_water_texts:
                rng = random.Random(f"{today_str}_group_{gid}")
                probe_pool = list(valid_pool)
                rng.shuffle(probe_pool)
                next_slot = len(unique_water_texts)
                for slot_i, candidate in enumerate(probe_pool):
                    if candidate not in unique_water_texts:
                        next_slot = slot_i
                        break
                return (signed_in if prefix_set else True), len(unique_water_texts), next_slot, last_msg_age_sec
        except Exception:
            continue
    return False, 0, 0, 999999.0


async def run_batch_for_group(
    client: TelegramClient,
    group_seq_num: int,
    group_id: int,
    group_name: str,
    start_delay_sec: float,
    round_index: int,
    round_key: str,
    total_rounds: int,
    is_signin_round: bool,
    water_slot_index: int,
) -> dict:
    """
    单个群在单轮中的执行过程：
    【铁律】无论任何情况，单轮在单个群内最多只发送 1 条消息（签到轮只发 1 条签到，水群轮只发 1 条水群）！
    【隐私保护】在 GitHub 云端公开环境中，绝不输出任何真实群名、群 ID 或发送文本内容！
    """
    masked_label = f"加密目标群 #{group_seq_num:02d}" if IS_CLOUD else f"{group_name} ({group_id})"
    stats = {
        "round_key": round_key,
        "group_seq": group_seq_num,
        "display_label": masked_label,
        "planned_total": 1,
        "success_count": 0,
        "fail_count": 0,
        "aborted": False,
        "errors": [],
        "start_time": "-",
        "end_time": "-",
    }

    if start_delay_sec > 0:
        log_info(
            f"⏳ [{masked_label}] 已排入本轮队列，将在 {start_delay_sec:.0f} 秒后错峰发送..."
        )
        await asyncio.sleep(start_delay_sec)

    stats["start_time"] = datetime.now(BJ_TZ).strftime("%H:%M:%S")

    if is_signin_round:
        prefix_msgs = [m.strip() for m in getattr(config, "FIXED_PREFIX_MESSAGES", ["签到"]) if str(m).strip()]
        msg = prefix_msgs[0] if prefix_msgs else "签到"
        tag = "每日独立签到"
    else:
        msg = pick_single_non_repeating_message(group_id, water_slot_index)
        tag = f"水群轮次(槽位#{water_slot_index + 1})"

    display_msg = "[内容已加密隐藏]" if IS_CLOUD else msg

    try:
        await send_one_message(client, group_id, msg)
        stats["success_count"] = 1
        log_info(f"✅ [{masked_label}] [{tag}] [单轮严格1条] 发送成功: {display_msg}")

    except SlowModeWaitError as e:
        reason = classify_tg_error(e)
        log_info(f"⚠️ [{masked_label}] [{tag}] {reason}")
        if e.seconds <= 90:
            await asyncio.sleep(e.seconds + 2)
            try:
                await send_one_message(client, group_id, msg)
                stats["success_count"] = 1
                log_info(f"✅ [{masked_label}] [{tag}] (慢速重试成功): {display_msg}")
            except Exception as retry_err:
                r_reason = classify_tg_error(retry_err)
                stats["fail_count"] = 1
                stats["errors"].append(f"{tag}: {r_reason}")
                log_info(f"❌ [{masked_label}] [{tag}] 重试仍失败: {r_reason}")
        else:
            stats["fail_count"] = 1
            stats["errors"].append(f"{tag}: {reason}")
            stats["aborted"] = True

    except FloodWaitError as e:
        reason = classify_tg_error(e)
        log_info(f"🛑 [{masked_label}] [{tag}] {reason}")
        if e.seconds <= 90:
            await asyncio.sleep(e.seconds + 3)
            try:
                await send_one_message(client, group_id, msg)
                stats["success_count"] = 1
                log_info(f"✅ [{masked_label}] [{tag}] (FloodWait重试成功): {display_msg}")
            except Exception as retry_err:
                r_reason = classify_tg_error(retry_err)
                stats["fail_count"] = 1
                stats["errors"].append(f"{tag}: {r_reason}")
                log_info(f"❌ [{masked_label}] [{tag}] 重试仍失败: {r_reason}")
        else:
            stats["fail_count"] = 1
            stats["errors"].append(f"{tag}: {reason}")
            stats["aborted"] = True

    except (
        ChatWriteForbiddenError,
        UserBannedInChannelError,
        ChannelPrivateError,
        ChatAdminRequiredError,
        PeerFloodError,
        AuthKeyDuplicatedError,
    ) as fatal_err:
        reason = classify_tg_error(fatal_err)
        stats["fail_count"] = 1
        stats["errors"].append(f"在 [{tag}] 中止: {reason}")
        stats["aborted"] = True
        log_info(
            f"❌ [{masked_label}] [{tag}] 遇到权限/封禁错误: {reason}"
        )

    except Exception as e:
        reason = classify_tg_error(e)
        stats["fail_count"] = 1
        stats["errors"].append(f"{tag}: {reason}")
        log_info(f"❌ [{masked_label}] [{tag}] 发送失败: {reason}")

    stats["end_time"] = datetime.now(BJ_TZ).strftime("%H:%M:%S")
    return stats


def write_summary_report(all_stats: list[dict], unresolved_targets: list[str], start_bj: str, end_bj: str, round_title: str):
    """输出每轮汇总报表（云端模式下 100% 隐藏所有群名、群 ID 与个人特征）"""
    all_stats_sorted = sorted(all_stats, key=lambda x: x["group_seq"])
    total_groups = len(all_stats_sorted)
    perfect_groups = sum(1 for s in all_stats_sorted if s["fail_count"] == 0 and s["success_count"] > 0)
    partial_or_failed_groups = total_groups - perfect_groups
    total_sent = sum(s["success_count"] for s in all_stats_sorted)
    total_failed = sum(s["fail_count"] for s in all_stats_sorted)

    log_info("=" * 80)
    log_info(f"📊 【{round_title} 执行结果汇总 (隐私加密脱敏模式)】")
    log_info(f"⏱️ 运行时间(北京): {start_bj} ~ {end_bj}")
    log_info(
        f"📌 群组总计: {total_groups} 个 (成功: {perfect_groups} 个 | 失败/中止: {partial_or_failed_groups} 个)"
    )
    log_info(f"✉️ 消息统计: 成功发出 {total_sent} 条 | 失败/跳过 {total_failed} 条")
    log_info("-" * 80)

    for s in all_stats_sorted:
        status_icon = "✅ 成功" if s["fail_count"] == 0 else ("🛑 中止/失败" if s["aborted"] else "⚠️ 部分失败")
        err_summary = "无" if not s["errors"] else " ； ".join(s["errors"])
        log_info(
            f"{status_icon} | {s['display_label']} | "
            f"成功: {s['success_count']}/{s['planned_total']} | 失败原因: {err_summary}"
        )
    log_info("=" * 80)

    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            md_lines = [
                f"## 📊 {round_title} 执行结果报告 (隐私脱敏)",
                f"- **运行时间 (北京时间)**：`{start_bj}` ~ `{end_bj}`",
                f"- **群组执行统计**：共 **{total_groups}** 个群（✅ 成功：**{perfect_groups}** 个 | ❌ 异常：**{partial_or_failed_groups}** 个）",
                f"- **消息发送统计**：成功发送 **{total_sent}** 条 | 失败/未发 **{total_failed}** 条",
                "",
                "| 状态 | 加密编号 | 成功 / 计划条数 | 备注 |",
                "| :--- | :--- | :---: | :--- |",
            ]
            for s in all_stats_sorted:
                status_badge = "✅ 成功" if s["fail_count"] == 0 else ("🛑 权限/封禁中止" if s["aborted"] else "⚠️ 失败")
                err_text = "—" if not s["errors"] else "<br>".join(s["errors"])
                md_lines.append(
                    f"| {status_badge} | **{s['display_label']}** | **{s['success_count']} / {s['planned_total']}** | {err_text} |"
                )
            md_lines.append("\n---\n")
            with open(summary_path, "a", encoding="utf-8") as sf:
                sf.write("\n".join(md_lines) + "\n")
        except Exception:
            pass


async def execute_one_round(
    round_index: int,
    round_key: str,
    raw_targets: list,
    total_rounds: int,
):
    """连接 Telegram 并执行单轮全群发送（每轮每群严格只发 1 条，绝不连发 2 条）"""
    session_str = os.getenv("TG_SESSION_STRING", "").strip() or getattr(config, "TG_SESSION_STRING", "").strip()
    if not session_str:
        log_info("❌ [错误] TG_SESSION_STRING 为空！")
        return

    start_bj = bj_now_str()
    round_title = f"第 {round_index + 1}/{total_rounds} 轮 [{round_key}]"
    log_info(f"🚀 [{round_title}] 正在连接 Telegram...")

    client = TelegramClient(
        StringSession(session_str),
        int(config.TG_API_ID),
        str(config.TG_API_HASH),
        proxy=get_proxy(),
        device_model="Desktop",
        system_version="Windows 11",
        app_version="5.6.3 x64",
        lang_code="en",
        system_lang_code="zh-CN",
        flood_sleep_threshold=30,
    )

    try:
        await asyncio.wait_for(client.connect(), timeout=30.0)
    except Exception as e:
        log_info(f"❌ 连接 Telegram 服务器失败: {classify_tg_error(e)}")
        return

    if not await client.is_user_authorized():
        log_info("❌ 登录凭证已失效！")
        await client.disconnect()
        return

    me = await client.get_me()
    already_signed, water_sent_today, next_unused_slot, last_msg_age_sec = await check_today_progress(client, me.id)
    signin_only_ids = {int(x) for x in getattr(config, "SIGNIN_ONLY_GROUP_IDS", []) if isinstance(x, int) or str(x).lstrip("-").isdigit()}

    # 跨班次容器交接防重保护：如果上一班次容器在 40 分钟内(2400秒)刚发过消息，直接跳过！
    is_manual_now = ("--now" in sys.argv) or (os.getenv("INPUT_MODE", "").strip().lower() == "now")
    if (not is_manual_now) and last_msg_age_sec < 2400:
        log_info(
            f"🛡️ [防连发/跨班次交接保护] 检测到距离上一条消息仅过去 {last_msg_age_sec / 60:.1f} 分钟 (< 40 分钟)！"
            f"自动跳过本轮，直接进入下一轮倒计时，绝不连续发送！"
        )
        await client.disconnect()
        return

    # 严格拆分【独立签到轮】与【单条水群轮】，确保任何一轮在任何群都只发 1 条消息！
    if not already_signed:
        is_signin_round = True
        water_slot_index = 0
        effective_targets = list(getattr(config, "TARGET_GROUP_IDS", raw_targets))
        log_info(
            f"🔔 [独立签到轮] 检测到今日 ({datetime.now(BJ_TZ).strftime('%Y-%m-%d')}) 尚未签到！"
            f"本轮仅执行【全群每日签到 (每群严格只发 1 条 '签到'，不发水群)】，覆盖全部 {len(effective_targets)} 个群！"
        )
    else:
        if water_sent_today >= 10 and not is_manual_now:
            log_info(f"🎉 [今日配额已满] 今日已完成签到且已累计发送 {water_sent_today}/10 条水群消息，本轮无需再发！")
            await client.disconnect()
            return

        is_signin_round = False
        water_slot_index = next_unused_slot
        effective_targets = [
            g for g in getattr(config, "TARGET_GROUP_IDS", raw_targets)
            if not (isinstance(g, int) or str(g).strip().lstrip("-").isdigit())
            or int(str(g).strip()) not in signin_only_ids
        ]
        log_info(
            f"✅ [单条水群轮] 今日已签到，已发水群 {water_sent_today}/10 条。"
            f"本轮为 {len(effective_targets)} 个水群严格各发 1 条 (今日第 {water_sent_today + 1}/10 条 | 槽位 #{water_slot_index + 1})，绝不连发！"
        )

    dialogs = await asyncio.wait_for(client.get_dialogs(), timeout=45.0)
    all_groups_map: dict[int, str] = {d.id: (d.name or str(d.id)) for d in dialogs if d.is_group}

    resolved_groups: list[tuple[int, int, str]] = []
    unresolved_targets: list[str] = []
    seen_ids = set()

    for seq_idx, item in enumerate(effective_targets, start=1):
        if isinstance(item, int) or (isinstance(item, str) and item.strip().lstrip("-").isdigit()):
            gid = int(str(item).strip())
            if gid not in seen_ids:
                seen_ids.add(gid)
                gname = all_groups_map.get(gid)
                if not gname:
                    try:
                        ent = await asyncio.wait_for(client.get_entity(gid), timeout=15.0)
                        gname = getattr(ent, "title", f"群组_{gid}")
                    except Exception as e:
                        unresolved_targets.append(f"Group#{seq_idx:02d} ({type(e).__name__})")
                        continue
                resolved_groups.append((seq_idx, gid, gname))

    if not resolved_groups:
        log_info("❌ [错误] 未匹配到任何可访问的目标群组！")
        await client.disconnect()
        return

    account_display = "[已加密隐藏账号]" if IS_CLOUD else me.first_name
    mode_desc = (
        "仅发送 1 条 '签到' (独立签到轮，不附带水群)"
        if is_signin_round
        else f"仅发送 1 条水群消息 (今日第 {water_sent_today + 1}/10 条)"
    )
    log_info(
        f"🎯 [{round_title}] 账号: {account_display} | 目标群: {len(resolved_groups)} 个 | 本轮内容: {mode_desc}"
    )

    shuffled_groups = list(resolved_groups)
    random.shuffle(shuffled_groups)

    g_delay_min = float(getattr(config, "GROUP_START_DELAY_MIN_SEC", 12))
    g_delay_max = float(getattr(config, "GROUP_START_DELAY_MAX_SEC", 25))

    tasks = []
    cumulative_delay = 0.0
    for idx, (seq_num, gid, gname) in enumerate(shuffled_groups):
        if idx > 0:
            cumulative_delay += random.uniform(g_delay_min, g_delay_max)
        tasks.append(
            run_batch_for_group(
                client, seq_num, gid, gname, cumulative_delay, round_index, round_key, total_rounds, is_signin_round, water_slot_index
            )
        )

    all_stats = await asyncio.gather(*tasks)
    end_bj = bj_now_str()
    write_summary_report(all_stats, unresolved_targets, start_bj, end_bj, round_title)
    await client.disconnect()


async def main():
    if not IS_CLOUD:
        with open(RUN_LOG_FILE, "w", encoding="utf-8") as f:
            f.write(f"=== Telegram 自动水群运行日志 ({bj_now_str()}) ===\n")

    if "--sync" in sys.argv:
        sync_schedule_to_github_yml()
        return

    rounds: list = list(getattr(config, "DAILY_WATER_ROUNDS", getattr(config, "SCHEDULE_BEIJING_TIMES", ["12:00"])))
    total_rounds = len(rounds)
    all_fallback: list = getattr(config, "TARGET_GROUP_IDS", [])

    # 如果通过命令行传入 --now 或手动选择 now 模式，则立即执行当前最近的一轮并退出
    input_mode = os.getenv("INPUT_MODE", "wait").strip().lower()
    if "--now" in sys.argv or input_mode == "now":
        upcoming = get_upcoming_rounds(set())
        r_idx, r_key, r_groups, _ = upcoming[0] if upcoming else (0, rounds[0], all_fallback, datetime.now(BJ_TZ))
        log_info(f"⚡ [立即执行模式] 正在立即执行第 {r_idx + 1}/{total_rounds} 轮 [{r_key}]...")
        await execute_one_round(r_idx, r_key, r_groups, total_rounds)
        return

    # 连续多轮精准时钟驻留引擎：
    # 容器启动后，在 5.4 小时驻留窗口内自动接力完成所有到点的黄金时段轮次（误差 0.0 秒）！
    container_start = datetime.now(BJ_TZ)
    executed_today: set[str] = set()
    rounds_completed_in_this_session = 0

    log_info(
        f"🌟 [黄金时段多轮驻留引擎已启动] 每日共 {total_rounds} 轮 ({rounds[0]} ~ {rounds[-1]})，单容器可持续接力 {MAX_CONTAINER_HOLD_SECONDS / 3600:.1f} 小时"
    )

    while True:
        upcoming = get_upcoming_rounds(executed_today)
        if not upcoming:
            break

        r_idx, r_key, r_groups, target_dt = upcoming[0]
        now_bj = datetime.now(BJ_TZ)
        elapsed_since_start = (now_bj - container_start).total_seconds()
        wait_sec = max(0.0, (target_dt - now_bj).total_seconds())

        # 检查等待本轮 + 执行本轮（约 6 分钟）是否会超出单容器 5.4 小时驻留上限
        if elapsed_since_start + wait_sec + 420 > MAX_CONTAINER_HOLD_SECONDS:
            if rounds_completed_in_this_session == 0:
                log_info(
                    f"✅ [配置预检完成] 下一轮为第 {r_idx + 1}/{total_rounds} 轮 (北京时间 {target_dt.strftime('%Y-%m-%d %H:%M:%S')}，"
                    f"距离现在 {wait_sec / 3600:.1f} 小时)，将由下一班次预唤醒容器接管执行！"
                )
            else:
                log_info(
                    f"🏁 [本班次圆满结束] 本次容器已连续精准完成 {rounds_completed_in_this_session} 轮任务！"
                    f"下一轮 ({target_dt.strftime('%H:%M')}) 将由排队候命的下一班次容器无缝接力。"
                )
            break

        # 精准倒计时对齐到本轮设定时间
        await wait_until_exact_beijing_time(target_dt, r_idx + 1, total_rounds, r_key)

        # 如果配置了微调随机偏移窗口（0~3 分钟），在此处微调
        win_mins = float(getattr(config, "RANDOM_START_WINDOW_MINUTES", 0))
        if win_mins > 0 and wait_sec > 0:
            rand_sec = random.randint(0, int(win_mins * 60))
            if rand_sec > 0:
                log_info(f"🎲 [自然微调偏移] 随机等待 {rand_sec} 秒后开始本轮发送...")
                await asyncio.sleep(rand_sec)

        await execute_one_round(r_idx, r_key, r_groups, total_rounds)

        today_tag = f"{target_dt.strftime('%Y-%m-%d')}_{r_key}"
        executed_today.add(today_tag)
        rounds_completed_in_this_session += 1


if __name__ == "__main__":
    asyncio.run(main())
