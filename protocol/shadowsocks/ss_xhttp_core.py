# ss_xhttp_core.py
# ══════════════════════════════════════════════════════════════════════════════
# Shadowsocks XHTTP Core — موتور مشترک session/quota/flow برای ترنسپورت
# XHTTP روی Shadowsocks (معادل protocol/vless/xhttp_core.py برای VLESS/Trojan).
# فایل‌های xhttshadstron.py / xhttshadpacketup.py / xhttshadstrup.py فقط
# route ها را تعریف می‌کنند و از این هسته استفاده می‌کنند.
#
# تفاوت اصلی با موتور VLESS/Trojan: اینجا بایت‌های خام آپلود هنوز رمزنگاری‌شده
# (AEAD) هستند و باید با _AEADStream مخصوص هر session رمزگشایی بشن؛ اولین
# payload رمزگشایی‌شده شامل هدر SOCKS5-like آدرس مقصد است (طبق spec شادوساکس).
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import secrets
import time
from datetime import datetime

from fastapi import Request, HTTPException

from main import (
    LINKS,
    LINKS_LOCK,
    connections,
    logger,
    is_link_allowed,
    save_state,
)
from protocol.vless.vless import check_and_use
from protocol.shadowsocks.shadowsocks import (
    _AEADStream,
    _tune_socket,
    parse_socks5_addr,
    derive_key,
    CIPHERS,
    DEFAULT_CIPHER,
)

XHTTP_BUF = 1024 * 1024
DOWNLINK_QUEUE_MAX = 512
SESSION_IDLE_TIMEOUT = 30
SESSION_IDLE_TIMEOUT_ACTIVE = 90
REAPER_INTERVAL = 10
TCP_CONNECT_TIMEOUT = 10.0

PACKET_UP_HIGH_WATER = 2 * 1024 * 1024

# ── تنظیمات QuotaGate تطبیقی ──────────────────────────────────────────────────
QUOTA_MIN_BATCH = 32 * 1024
QUOTA_MAX_BATCH = 2 * 1024 * 1024
QUOTA_START_BATCH = 128 * 1024
QUOTA_CHECK_INTERVAL = 0.25

# ── تنظیمات AdaptiveFlow (AIMD) ───────────────────────────────────────────────
FLOW_MIN_HW = 256 * 1024
FLOW_MAX_HW = 32 * 1024 * 1024
FLOW_START_HW = 4 * 1024 * 1024
FLOW_FAST_DRAIN_MS = 2.0
FLOW_SLOW_DRAIN_MS = 25.0

ss_xhttp_sessions: dict = {}
XHTTP_LOCK = asyncio.Lock()

FINGERPRINTS = {
    "chrome": {
        "content-type": "application/grpc",
        "cache-control": "no-cache, no-store",
        "x-accel-buffering": "no",
        "server": "cloudflare",
    },
    "plain": {
        "content-type": "application/octet-stream",
        "cache-control": "no-store",
        "x-accel-buffering": "no",
    },
}
DEFAULT_FINGERPRINT = "chrome"


def resp_headers(fp: str) -> dict:
    return dict(FINGERPRINTS.get(fp, FINGERPRINTS[DEFAULT_FINGERPRINT]))


def req_client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "نامشخص"


class QuotaGate:
    """نسخه‌ی تطبیقی: batch quota check بر اساس EWMA نرخ ترافیک هر session."""
    __slots__ = ("uuid", "pending", "last_check", "ok", "batch_bytes", "rate_ewma")

    def __init__(self, uuid: str):
        self.uuid = uuid
        self.pending = 0
        self.last_check = time.monotonic()
        self.ok = True
        self.batch_bytes = QUOTA_START_BATCH
        self.rate_ewma = 0.0

    async def add(self, nbytes: int) -> bool:
        if not self.ok:
            return False
        self.pending += nbytes
        now = time.monotonic()
        elapsed = now - self.last_check
        if self.pending >= self.batch_bytes or elapsed >= QUOTA_CHECK_INTERVAL:
            flush, self.pending = self.pending, 0
            if elapsed > 0:
                inst_rate = flush / elapsed
                self.rate_ewma = inst_rate if self.rate_ewma == 0 else (0.7 * self.rate_ewma + 0.3 * inst_rate)
                target = int(self.rate_ewma * QUOTA_CHECK_INTERVAL)
                self.batch_bytes = max(QUOTA_MIN_BATCH, min(QUOTA_MAX_BATCH, target or QUOTA_MIN_BATCH))
            self.last_check = now
            try:
                self.ok = await check_and_use(self.uuid, flush)
            except Exception as exc:
                logger.error(f"SS-XHTTP QuotaGate.add failed uuid={self.uuid[:8]}: {type(exc).__name__}: {exc}")
                self.ok = False
            return self.ok
        return True

    async def flush(self) -> bool:
        if self.pending:
            flush, self.pending = self.pending, 0
            try:
                self.ok = self.ok and await check_and_use(self.uuid, flush)
            except Exception as exc:
                logger.error(f"SS-XHTTP QuotaGate.flush failed uuid={self.uuid[:8]}: {type(exc).__name__}: {exc}")
                self.ok = False
        return self.ok


class AdaptiveFlow:
    """high-water تطبیقی برای drain(), مثل AIMD در TCP congestion control."""
    __slots__ = ("high_water", "last_drain_ms")

    def __init__(self):
        self.high_water = FLOW_START_HW
        self.last_drain_ms = 0.0

    def should_drain(self, buf_size: int) -> bool:
        return buf_size > self.high_water

    async def drain(self, writer: asyncio.StreamWriter):
        t0 = time.monotonic()
        await writer.drain()
        elapsed_ms = (time.monotonic() - t0) * 1000
        self.last_drain_ms = elapsed_ms
        if elapsed_ms < FLOW_FAST_DRAIN_MS:
            self.high_water = min(FLOW_MAX_HW, int(self.high_water * 1.5) + 65536)
        elif elapsed_ms > FLOW_SLOW_DRAIN_MS:
            self.high_water = max(FLOW_MIN_HW, self.high_water // 2)


async def check_link(uuid: str):
    """لینک shadowsocks معتبر و مجاز را برمی‌گرداند، وگرنه 403."""
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    proto = (link or {}).get("protocol", "")
    is_ss = proto == "shadowsocks" or proto.startswith("shadowsocks-xhttp-")
    if not link or not is_ss or not is_link_allowed(link):
        raise HTTPException(status_code=403, detail="not authorized")
    return link


async def get_or_create_session(uuid: str, mode: str, session_id: str, link: dict, ip: str = "نامشخص") -> dict:
    """Session بر اساس session_id که خودِ کلاینت در URL می‌فرسته، lazily ساخته می‌شه."""
    async with XHTTP_LOCK:
        sess = ss_xhttp_sessions.get(session_id)
        if sess is not None:
            sess["last_seen"] = time.time()
            return sess

        cipher_name = link.get("ss_cipher", DEFAULT_CIPHER)
        info = CIPHERS.get(cipher_name)
        if not info:
            raise HTTPException(status_code=400, detail="unsupported cipher")
        master_key = derive_key(link.get("ss_password", ""), info["key_len"])
        stream = _AEADStream(master_key, cipher_name)

        conn_id = secrets.token_urlsafe(6)
        connections[conn_id] = {
            "uuid": uuid,
            "ip": ip,
            "connected_at": datetime.now().isoformat(),
            "bytes": 0,
            "transport": f"ss-xhttp-{mode}",
        }
        sess = {
            "uuid": uuid, "mode": mode, "stream": stream, "writer": None,
            "downlink_task": None,
            "down_q": asyncio.Queue(maxsize=DOWNLINK_QUEUE_MAX),
            "last_seen": time.time(),
            "conn_id": conn_id, "tcp_open": False, "closed": False,
            "seq_buf": {}, "next_seq": 0,
            "gate": None,   # لازی: QuotaGate تطبیقی مخصوص stream-up
            "flow": None,   # لازی: AdaptiveFlow مخصوص stream-up
            "upload_lock": asyncio.Lock(),
        }
        ss_xhttp_sessions[session_id] = sess
        logger.info(f"new SS-XHTTP[{mode}] session [{session_id[:8]}] uuid={uuid[:8]} ip={ip}")
        return sess


async def teardown(session_id: str, reason: str = ""):
    async with XHTTP_LOCK:
        sess = ss_xhttp_sessions.pop(session_id, None)
    if not sess:
        return
    sess["closed"] = True
    task = sess.get("downlink_task")
    if task:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
    writer = sess.get("writer")
    if writer:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    connections.pop(sess.get("conn_id"), None)
    dq = sess.get("down_q")
    if dq:
        try:
            dq.put_nowait(None)
        except Exception:
            pass
    suffix = f" reason={reason}" if reason else ""
    logger.info(f"closed SS-XHTTP[{sess.get('mode')}] [{session_id[:8]}] total={len(ss_xhttp_sessions)}{suffix}")
    asyncio.create_task(save_state())


async def _reaper():
    while True:
        await asyncio.sleep(REAPER_INTERVAL)
        now = time.time()
        async with XHTTP_LOCK:
            stale = []
            for sid, s in ss_xhttp_sessions.items():
                idle = now - s["last_seen"]
                if s.get("tcp_open"):
                    if idle > SESSION_IDLE_TIMEOUT_ACTIVE:
                        stale.append(sid)
                else:
                    if idle > SESSION_IDLE_TIMEOUT:
                        stale.append(sid)
        for sid in stale:
            await teardown(sid, reason="idle-timeout")


_reaper_started = False


def ensure_reaper():
    global _reaper_started
    if not _reaper_started:
        asyncio.create_task(_reaper())
        _reaper_started = True


async def _pump_tcp_to_queue(session_id: str, uuid: str, reader: asyncio.StreamReader, sess: dict):
    """TCP مقصد -> رمزنگاری AEAD -> صف دانلینک (که downstream_gen از اون می‌خونه)."""
    down_q = sess["down_q"]
    stream = sess["stream"]
    conn_id = sess["conn_id"]
    cached_conn = connections.get(conn_id)
    gate = QuotaGate(uuid)
    close_reason = "remote-eof"
    try:
        while True:
            try:
                data = await reader.read(XHTTP_BUF)
            except (ConnectionResetError, OSError) as exc:
                close_reason = f"tcp-read-error: {type(exc).__name__}: {exc}"
                logger.warning(f"SS-XHTTP[{session_id[:8]}] downlink read error: {close_reason}")
                break
            if not data:
                break
            if not await gate.add(len(data)):
                close_reason = "quota-exceeded"
                logger.warning(f"SS-XHTTP[{session_id[:8]}] downlink quota exceeded, closing")
                break
            if cached_conn is not None:
                cached_conn["bytes"] += len(data)
            frame = stream.encrypt_chunk(data)
            await down_q.put(frame)
    except asyncio.CancelledError:
        close_reason = "cancelled"
    except Exception as exc:
        close_reason = f"unexpected: {type(exc).__name__}: {exc}"
        logger.error(f"SS-XHTTP[{session_id[:8]}] downlink pump crashed: {type(exc).__name__}: {exc}")
    finally:
        await gate.flush()
        await teardown(session_id, reason=close_reason)


async def feed_and_relay(session_id: str, uuid: str, sess: dict, data: bytes):
    """
    بایت‌های خام آپلود (هنوز رمزنگاری‌شده) رو به AEAD stream این session تغذیه
    می‌کنه؛ هر payload رمزگشایی‌شده‌ی کامل رو یا برای باز کردن TCP (اولین
    payload، شامل هدر SOCKS5) یا برای نوشتن مستقیم روی TCP استفاده می‌کنه.
    """
    stream = sess["stream"]
    stream.feed(data)
    try:
        chunks = list(stream.try_decrypt_chunks())
    except ValueError:
        await teardown(session_id, reason="bad-aead-frame")
        raise HTTPException(status_code=400, detail="bad aead frame")

    for payload in chunks:
        if not payload:
            continue

        if sess["writer"] is None:
            try:
                address, port, hlen = parse_socks5_addr(payload)
            except Exception as exc:
                logger.error(f"SS-XHTTP[{session_id[:8]}] bad socks5 header: {type(exc).__name__}: {exc}")
                await teardown(session_id, reason=f"bad-socks5-header: {type(exc).__name__}")
                raise HTTPException(status_code=400, detail="bad socks5 header")
            initial_data = payload[hlen:]

            if not await check_and_use(uuid, len(payload)):
                await teardown(session_id, reason="quota/disabled/unknown")
                raise HTTPException(status_code=403, detail="quota/disabled/unknown")

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port), timeout=TCP_CONNECT_TIMEOUT
                )
            except Exception as exc:
                logger.error(f"SS-XHTTP[{session_id[:8]}] connect FAILED -> {address}:{port}: {type(exc).__name__}: {exc}")
                await teardown(session_id, reason=f"connect-failed: {type(exc).__name__}")
                raise

            _tune_socket(writer)
            sess["writer"] = writer
            sess["tcp_open"] = True
            logger.info(f"connect SS-XHTTP[{sess['mode']}] [{session_id[:8]}] -> {address}:{port}")

            if initial_data:
                writer.write(initial_data)
                await writer.drain()

            sess["downlink_task"] = asyncio.create_task(
                _pump_tcp_to_queue(session_id, uuid, reader, sess)
            )
        else:
            if not await check_and_use(uuid, len(payload)):
                await teardown(session_id, reason="quota/disabled/unknown")
                raise HTTPException(status_code=403, detail="quota/disabled/unknown")
            if sess["writer"].is_closing():
                raise ConnectionError("transport closing")
            sess["writer"].write(payload)


def downstream_gen(sess: dict):
    async def gen():
        try:
            while True:
                chunk = await sess["down_q"].get()
                if chunk is None:
                    break
                sess["last_seen"] = time.time()
                yield chunk
        finally:
            pass
    return gen()
