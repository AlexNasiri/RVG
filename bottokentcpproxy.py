# bottokentcpproxy.py
# ══════════════════════════════════════════════════════════════════════════════
# ساخت خودکار TCP Proxy روی Railway
# دو حالت:
#   - BLACKLIST (پیش‌فرض): هر دامنه‌ای غیر از دامنه‌های داخل BLACKLIST_DOMAINS قبول می‌شود.
#   - WHITELIST: فقط دامنه‌هایی که کاربر مشخص کرده قبول می‌شوند (برای جستجوی دامنه‌ی دلخواه).
# برای سرعت بالا، درخواست‌ها به‌صورت موازی (چند تلاش هم‌زمان) ارسال می‌شوند.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import os
import time
import logging
from collections import deque
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("RVG-Gateway")

GRAPHQL_URL = "https://backboard.railway.app/graphql/v2"

# ──────────────────────────────────────────────────────────────────────────────
# دامنه‌هایی که قبول نمی‌شوند (حالت پیش‌فرض بلک‌لیست).
# ──────────────────────────────────────────────────────────────────────────────
_DEFAULT_BLACKLIST: set[str] = set()

KNOWN_DOMAINS: tuple[str, ...] = (
    "tokaido.proxy.rlwy.net", "shuttle.proxy.rlwy.net", "hayabusa.proxy.rlwy.net",
    "yamabiko.proxy.rlwy.net", "crossover.proxy.rlwy.net", "tramway.proxy.rlwy.net",
    "autorack.proxy.rlwy.net", "shinkansen.proxy.rlwy.net", "roundhouse.proxy.rlwy.net",
    "turntable.proxy.rlwy.net", "metro.proxy.rlwy.net", "reseau.proxy.rlwy.net",
    "junction.proxy.rlwy.net", "switchback.proxy.rlwy.net", "yamanote.proxy.rlwy.net",
    "zephyr.proxy.rlwy.net", "thomas.proxy.rlwy.net", "centerbeam.proxy.rlwy.net",
    "switchyard.proxy.rlwy.net", "shortline.proxy.rlwy.net", "viaduct.proxy.rlwy.net",
    "ballast.proxy.rlwy.net", "kodama.proxy.rlwy.net", "interchange.proxy.rlwy.net",
    "hopper.proxy.rlwy.net", "mainline.proxy.rlwy.net", "trolley.proxy.rlwy.net",
)


def _load_blacklist() -> set[str]:
    bl = set(_DEFAULT_BLACKLIST)
    extra = os.environ.get("BOT_TCP_PROXY_BLACKLIST", "")
    for item in extra.split(","):
        item = item.strip().rstrip(".").lower()
        if item:
            bl.add(item)
    return bl


BLACKLIST_DOMAINS = _load_blacklist()

MAX_ATTEMPTS = int(os.environ.get("BOT_TCP_PROXY_MAX_ATTEMPTS", 300))

# چند درخواست هم‌زمان (موازی) در هر راند ارسال شود — برای سرعت بالا
CONCURRENCY = int(os.environ.get("BOT_TCP_PROXY_CONCURRENCY", 8))

# تاخیر پایه بین راندها (وقتی ریت‌لیمیت نخوریم صفر است = سریع‌ترین حالت)
DELAY_SEC = float(os.environ.get("BOT_TCP_PROXY_DELAY", 0))
MAX_BACKOFF = 15.0

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
TOKEN_FILE = DATA_DIR / ".bot_tcp_proxy_token"

MUTATION_CREATE = """
mutation TcpProxyCreate($environmentId: String!, $serviceId: String!, $applicationPort: Int!) {
  tcpProxyCreate(input: {
    environmentId: $environmentId,
    serviceId: $serviceId,
    applicationPort: $applicationPort
  }) {
    id
    domain
    proxyPort
    applicationPort
  }
}
"""

MUTATION_DELETE = """
mutation TcpProxyDelete($id: String!) {
  tcpProxyDelete(id: $id)
}
"""

bot_proxy_state = {
    "running": False,
    "progress": 0,
    "attempts": 0,
    "result": None,
    "error": None,
    "stopped_by_user": False,
    "mode": "blacklist",       # "blacklist" | "whitelist"
    "target_domains": [],      # فقط در حالت whitelist پر می‌شود
}
bot_proxy_log: deque = deque(maxlen=300)
_task: Optional[asyncio.Task] = None

# قفلی برای جلوگیری از دوبار "برنده شدن" هم‌زمان در حالت موازی
_win_lock: Optional[asyncio.Lock] = None


def _mask(token: str) -> str:
    if not token or len(token) <= 8:
        return "***"
    return f"{token[:4]}…{token[-4:]}"


def _log(msg: str):
    bot_proxy_log.append({"time": time.time(), "msg": msg})
    logger.info(f"BotTcpProxy: {msg}")


def get_status() -> dict:
    return {
        **bot_proxy_state,
        "has_token": has_saved_token(),
        "blacklist": sorted(BLACKLIST_DOMAINS),
        "known_domains": list(KNOWN_DOMAINS),
        "logs": list(bot_proxy_log)[-100:],
    }


def has_saved_token() -> bool:
    try:
        return TOKEN_FILE.exists() and bool(TOKEN_FILE.read_text(encoding="utf-8").strip())
    except Exception:
        return False


def load_token() -> Optional[str]:
    try:
        if TOKEN_FILE.exists():
            val = TOKEN_FILE.read_text(encoding="utf-8").strip()
            return val or None
    except Exception as exc:
        logger.warning(f"BotTcpProxy: خواندن توکن ذخیره‌شده ناموفق بود: {exc}")
    return None


def save_token(token: str):
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        TOKEN_FILE.write_text(token.strip(), encoding="utf-8")
        try:
            os.chmod(TOKEN_FILE, 0o600)
        except Exception:
            pass
    except Exception as exc:
        logger.warning(f"BotTcpProxy: ذخیره‌ی توکن روی دیسک ناموفق بود: {exc}")


def clear_token():
    try:
        TOKEN_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def get_service_context() -> tuple[str, str]:
    service_id = os.environ.get("RAILWAY_SERVICE_ID")
    environment_id = os.environ.get("RAILWAY_ENVIRONMENT_ID")
    if not service_id or not environment_id:
        raise RuntimeError(
            "RAILWAY_SERVICE_ID / RAILWAY_ENVIRONMENT_ID پیدا نشد — "
            "این قابلیت فقط وقتی پنل روی خودِ Railway دیپلوی شده باشه کار می‌کند."
        )
    return service_id, environment_id


def _norm_domain(d: str) -> str:
    return (d or "").strip().rstrip(".").lower()


def _is_blacklisted(domain: str) -> bool:
    return _norm_domain(domain) in BLACKLIST_DOMAINS


class _RateLimited(Exception):
    pass


class _AuthError(Exception):
    """فقط برای خطاهای واقعیِ احراز هویت (توکن نامعتبر) — تنها موردی که باید کل فرآیند را متوقف کند."""
    pass


async def _gql(client: httpx.AsyncClient, token: str, query: str, variables: dict) -> dict:
    resp = await client.post(
        GRAPHQL_URL,
        json={"query": query, "variables": variables},
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        timeout=20.0,
    )
    if resp.status_code == 401:
        raise _AuthError("توکن Railway نامعتبر است یا دسترسی کافی ندارد")
    if resp.status_code == 429:
        raise _RateLimited()
    resp.raise_for_status()
    data = resp.json()
    if data.get("errors"):
        msg = "; ".join(e.get("message", "خطای نامشخص") for e in data["errors"])
        # این یک خطای GraphQL معمولی است (مثلاً تداخل موقتی هنگام ساخت هم‌زمان چند پروکسی)
        # و نباید کل فرآیند را متوقف کند — فقط این تلاش را rejected می‌کنیم.
        raise RuntimeError(f"خطای GraphQL: {msg}")
    return data.get("data", {})


async def _create_proxy(client: httpx.AsyncClient, token: str, service_id: str,
                         environment_id: str, application_port: int) -> dict:
    data = await _gql(client, token, MUTATION_CREATE, {
        "environmentId": environment_id,
        "serviceId": service_id,
        "applicationPort": application_port,
    })
    return data["tcpProxyCreate"]


async def _delete_proxy(client: httpx.AsyncClient, token: str, proxy_id: str):
    try:
        await _gql(client, token, MUTATION_DELETE, {"id": proxy_id})
    except Exception as exc:
        _log(f"⚠ حذف proxy نامطلوب ({proxy_id[:8]}…) ناموفق بود: {exc}")


def _domain_accepted(domain: str, mode: str, whitelist: Optional[set[str]]) -> bool:
    if mode == "whitelist":
        return domain in (whitelist or set())
    return not _is_blacklisted(domain)


async def _single_attempt(client: httpx.AsyncClient, token: str, service_id: str,
                           environment_id: str, application_port: int,
                           attempt_no: int, winner_holder: dict,
                           mode: str, whitelist: Optional[set[str]]):
    """یک تلاش برای ساخت پروکسی. اگر دامنه قابل قبول بود و هنوز برنده‌ای اعلام نشده، این را برنده می‌کند."""
    global _win_lock
    try:
        proxy = await _create_proxy(client, token, service_id, environment_id, application_port)
    except _AuthError as exc:
        # این تنها خطای واقعاً fatal است (توکن نامعتبر)
        return ("fatal", str(exc))
    except _RateLimited:
        return "rate_limited"
    except RuntimeError as exc:
        # خطای GraphQL معمولی (مثلاً تداخل موقتی) — قابل تلاش مجدد است، نباید کل کار را متوقف کند
        _log(f"⚠ خطای موقتی (GraphQL) در تلاش {attempt_no}: {exc}")
        return "retry"
    except Exception as exc:
        _log(f"⚠ خطای موقتی در تلاش {attempt_no}: {exc}")
        return "retry"

    domain_raw = proxy.get("domain", "")
    domain = _norm_domain(domain_raw)
    proxy_id = proxy.get("id")

    if not _domain_accepted(domain, mode, whitelist):
        _log(f"تلاش {attempt_no}: دامنه‌ی نامطلوب → {domain_raw} — حذف می‌شود")
        await _delete_proxy(client, token, proxy_id)
        return "rejected"

    # دامنه قابل قبول است — سعی می‌کنیم برنده شویم
    async with _win_lock:
        if winner_holder.get("result") is not None:
            # یک تلاش دیگر زودتر برنده شده، این یکی را حذف می‌کنیم
            await _delete_proxy(client, token, proxy_id)
            return "discarded_after_win"
        winner_holder["result"] = {
            "domain": domain,
            "port": proxy.get("proxyPort"),
            "application_port": proxy.get("applicationPort"),
            "id": proxy_id,
        }
    _log(f"✅ موفق! تلاش {attempt_no}: دامنه‌ی قابل قبول → {domain_raw} — پورت TCP: {proxy.get('proxyPort')}")
    return "won"


async def run_bot_proxy_job(token: str, application_port: int,
                             mode: str = "blacklist",
                             whitelist: Optional[set[str]] = None,
                             extra_blacklist: Optional[set[str]] = None):
    global _win_lock
    _win_lock = asyncio.Lock()

    job_blacklist = set(BLACKLIST_DOMAINS) | (extra_blacklist or set())

    bot_proxy_state.update({
        "running": True, "progress": 0, "attempts": 0,
        "result": None, "error": None, "stopped_by_user": False,
        "mode": mode, "target_domains": sorted(whitelist) if whitelist else [],
    })
    bot_proxy_log.clear()
    if mode == "whitelist":
        _log(
            f"شروع؛ حالت جستجوی دامنه‌ی دلخواه ({len(whitelist or [])} دامنه هدف) — "
            f"همزمانی: {CONCURRENCY} — پورت اپلیکیشن {application_port} — توکن {_mask(token)}"
        )
        _log(f"دامنه‌های هدف: {', '.join(sorted(whitelist)) if whitelist else '(خالی)'}")
    else:
        _log(
            f"شروع؛ حالت بلک‌لیست ({len(BLACKLIST_DOMAINS)} دامنه مسدود) — "
            f"همزمانی: {CONCURRENCY} — پورت اپلیکیشن {application_port} — توکن {_mask(token)}"
        )
        _log(f"بلک‌لیست: {', '.join(sorted(BLACKLIST_DOMAINS)) or '(خالی)'}")

    try:
        service_id, environment_id = get_service_context()
        _log(f"سرویس شناسایی شد (service={service_id[:8]}… env={environment_id[:8]}…)")
    except RuntimeError as exc:
        bot_proxy_state["running"] = False
        bot_proxy_state["error"] = str(exc)
        _log(f"❌ {exc}")
        return

    winner_holder: dict = {"result": None}
    backoff = DELAY_SEC
    total_attempts = 0

    try:
        async with httpx.AsyncClient() as client:
            while total_attempts < MAX_ATTEMPTS and winner_holder["result"] is None:
                batch_size = min(CONCURRENCY, MAX_ATTEMPTS - total_attempts)
                tasks = []
                for i in range(batch_size):
                    total_attempts += 1
                    tasks.append(
                        _single_attempt(
                            client, token, service_id, environment_id,
                            application_port, total_attempts, winner_holder,
                            mode, whitelist,
                        )
                    )

                bot_proxy_state["attempts"] = total_attempts
                bot_proxy_state["progress"] = min(99, int(total_attempts / MAX_ATTEMPTS * 100))

                results = await asyncio.gather(*tasks, return_exceptions=True)

                # ── مهم: اول چک می‌کنیم آیا در همین batch برنده پیدا شده ──
                # اگر پیدا شده، حتی اگر یکی از تلاش‌های موازیِ دیگر همزمان خطا داده باشد،
                # آن خطا نباید موفقیت را نادیده بگیرد و کل فرآیند را متوقف کند.
                if winner_holder["result"] is not None:
                    break

                fatal_error = None
                any_rate_limited = False
                for r in results:
                    if isinstance(r, Exception):
                        _log(f"⚠ خطای غیرمنتظره: {r}")
                        continue
                    if isinstance(r, tuple) and r[0] == "fatal":
                        fatal_error = r[1]
                    elif r == "rate_limited":
                        any_rate_limited = True

                if fatal_error:
                    bot_proxy_state["running"] = False
                    bot_proxy_state["error"] = fatal_error
                    _log(f"❌ توقف: {fatal_error}")
                    return

                if any_rate_limited:
                    backoff = min(MAX_BACKOFF, max(1.0, backoff * 1.7))
                    _log(f"⏳ ریت‌لیمیت ریلوی — {backoff:.1f} ثانیه صبر می‌کنیم...")
                    await asyncio.sleep(backoff)
                else:
                    backoff = DELAY_SEC
                    if DELAY_SEC:
                        await asyncio.sleep(DELAY_SEC)

        if winner_holder["result"] is not None:
            bot_proxy_state.update({
                "running": False,
                "progress": 100,
                "result": winner_holder["result"],
            })
        else:
            bot_proxy_state["running"] = False
            if mode == "whitelist":
                bot_proxy_state["error"] = (
                    f"بعد از {total_attempts} تلاش، هیچ‌کدام از دامنه‌های هدف پیدا نشد"
                )
            else:
                bot_proxy_state["error"] = (
                    f"بعد از {total_attempts} تلاش، هیچ دامنه‌ی قابل‌قبولی (خارج از بلک‌لیست) پیدا نشد"
                )
            _log(f"❌ {bot_proxy_state['error']}")

    except asyncio.CancelledError:
        bot_proxy_state.update({
            "running": False,
            "error": "فرآیند توسط کاربر متوقف شد",
            "stopped_by_user": True,
        })
        _log("⏹ فرآیند توسط کاربر متوقف شد")


def start_job(token: Optional[str], application_port: int,
              mode: str = "blacklist",
              target_domains: Optional[list[str]] = None,
              extra_blacklist_domains: Optional[list[str]] = None):
    global _task
    token = (token or "").strip()
    if not token:
        token = load_token() or ""
    if not token:
        raise RuntimeError("توکن Railway وارد نشده و توکن ذخیره‌شده‌ای هم وجود ندارد")
    if bot_proxy_state["running"]:
        raise RuntimeError("یک فرآیند ساخت TCP Proxy از قبل در حال اجراست")

    whitelist = None
    if mode == "whitelist":
        whitelist = {_norm_domain(d) for d in (target_domains or []) if _norm_domain(d)}
        if not whitelist:
            raise RuntimeError("برای حالت جستجوی دامنه‌ی دلخواه، حداقل باید یک دامنه وارد کنید")

    extra_bl = {_norm_domain(d) for d in (extra_blacklist_domains or []) if _norm_domain(d)}

    save_token(token)
    _task = asyncio.create_task(run_bot_proxy_job(token, application_port, mode, whitelist, extra_bl))
    return _task


def stop_job() -> bool:
    global _task
    if _task and not _task.done():
        _task.cancel()
        return True
    return False


def add_to_blacklist(domain: str):
    d = _norm_domain(domain)
    if d:
        BLACKLIST_DOMAINS.add(d)
        _log(f"➕ دامنه به بلک‌لیست اضافه شد: {d}")


def remove_from_blacklist(domain: str):
    d = _norm_domain(domain)
    BLACKLIST_DOMAINS.discard(d)
    _log(f"➖ دامنه از بلک‌لیست حذف شد: {d}")


# ══════════════════════════════════════════════════════════════════════════════
# ساخت/حذف TCP Proxy عمومی برای یک پورت دلخواه — بدون محدودیت به دامنه‌ی خاص
# با استفاده از توکنی که کاربر یک‌بار ذخیره کرده — این توابع توسط main.py
# هنگام ساخت/حذف/تغییر پورت کانفیگ‌های Telegram Proxy صدا زده می‌شوند.
# ══════════════════════════════════════════════════════════════════════════════

async def create_public_proxy_for_port(application_port: int) -> dict:
    token = load_token()
    if not token:
        raise RuntimeError("توکن Railway ذخیره نشده — ابتدا یک‌بار از بخش Bot TCP Proxy توکن را وارد کنید")

    service_id, environment_id = get_service_context()
    async with httpx.AsyncClient() as client:
        proxy = await _create_proxy(client, token, service_id, environment_id, application_port)

    return {
        "id": proxy.get("id"),
        "domain": _norm_domain(proxy.get("domain", "")),
        "port": proxy.get("proxyPort"),
        "application_port": proxy.get("applicationPort"),
    }


async def delete_public_proxy(proxy_id: str):
    token = load_token()
    if not token or not proxy_id:
        return
    async with httpx.AsyncClient() as client:
        await _delete_proxy(client, token, proxy_id)