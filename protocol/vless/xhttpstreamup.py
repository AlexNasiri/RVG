# xhttpstreamup.py
# ══════════════════════════════════════════════════════════════════════════════
# XHTTP — آپلینک stream-up (POST(های) پیوسته روی یک session) برای VLESS / Trojan
# منطق اصلی (session, quota, adaptive flow) در xhttp_core.py قرار دارد.
# ══════════════════════════════════════════════════════════════════════════════

import time
import traceback
from datetime import datetime

from fastapi import APIRouter, Request, HTTPException
from starlette.requests import ClientDisconnect

from main import stats, connections, error_logs, logger
from protocol.vless.xhttp_core import (
    _AdaptiveFlow,
    _QuotaGate,
    ensure_reaper,
    _get_or_create_session,
    _open_tcp_for_session,
    _req_client_ip,
    _teardown,
)

router = APIRouter()


# ══════════════════════════════ STREAM-UP (POST(های) پیوسته روی یک session) ══════════════════════════════
# نکته‌ی مهم: پروتکل XHTTP اجازه می‌ده کلاینت برای یک session چند POST جداگانه و
# پشت‌سرهم بفرسته (rotation). وقتی کلاینت یک POST رو می‌بنده، این یک قطع طبیعیِ
# «این درخواست» است، نه قطع کل تونل — پس فقط از این تابع خارج می‌شیم، بدون اینکه
# TCP/session رو تخریب کنیم؛ POST بعدی با همون session_id ادامه می‌ده.
@router.post("/xhttp-siz10/stream-up/{uuid}/{session_id}")
async def stream_up_upload(uuid: str, session_id: str, request: Request):
    ensure_reaper()
    sess = await _get_or_create_session(uuid, "stream-up", session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    gate = sess.get("gate")
    if gate is None:
        gate = _QuotaGate(uuid)
        sess["gate"] = gate

    flow = sess.get("flow")
    if flow is None:
        flow = _AdaptiveFlow()
        sess["flow"] = flow

    upload_lock = sess["upload_lock"]
    conn = connections.get(sess["conn_id"])
    if conn is None:
        # session بین این چک و الان بسته شده
        raise HTTPException(status_code=404, detail="session closed")

    async with upload_lock:  # جلوگیری از نوشتن هم‌زمان دو POST روی یک writer
        writer = sess["writer"]  # ممکنه هنوز None باشه

        try:
            async for chunk in request.stream():
                if not chunk:
                    continue
                sess["last_seen"] = time.time()

                if not await gate.add(len(chunk)):
                    logger.warning(f"XHTTP[stream-up] [{session_id[:8]}] quota exceeded during upload")
                    raise HTTPException(status_code=403, detail="quota/disabled/unknown")

                stats["total_requests"] += 1
                conn["bytes"] += len(chunk)

                if writer is None:
                    await _open_tcp_for_session(session_id, uuid, sess, chunk)
                    writer = sess["writer"]
                    continue

                if writer.is_closing():
                    raise ConnectionError("transport closing (remote already closed)")
                writer.write(chunk)
                if flow.should_drain(writer.transport.get_write_buffer_size()):
                    await flow.drain(writer)

        except ClientDisconnect:
            # در stream-up، کلاینت uplink رو می‌بنده تا downlink ادامه بده.
            # TCP را نمی‌کشیم — writer رو flush می‌کنیم تا داده‌های pending به remote برسه،
            # ولی session/TCP زنده می‌مونه تا downlink بتونه ادامه بده.
            await gate.flush()
            if sess.get("writer") and not sess["writer"].is_closing():
                try:
                    await sess["writer"].drain()
                except Exception:
                    pass
            logger.info(f"XHTTP[stream-up] [{session_id[:8]}] uplink closed by client, downlink still active")
            return

        except HTTPException as exc:
            logger.warning(f"XHTTP[stream-up] [{session_id[:8]}] HTTPException: {exc.status_code} {exc.detail}")
            await gate.flush()
            await _teardown(session_id, reason=f"http-{exc.status_code}")
            raise

        except (ConnectionResetError, BrokenPipeError, ConnectionError) as exc:
            # اینجا مشکل واقعاً TCP سمت مقصد (یا writer) هست، نه رفتار عادی کلاینت
            # پس باید کل session رو ببندیم چون دیگه قابل ادامه نیست.
            logger.warning(f"XHTTP[stream-up] [{session_id[:8]}] connection error: {type(exc).__name__}: {exc}")
            error_logs.append({"error": f"stream-up conn error: {type(exc).__name__}: {exc}", "time": datetime.now().isoformat()})
            await gate.flush()
            await _teardown(session_id, reason=f"conn-error: {type(exc).__name__}")
            raise HTTPException(status_code=502, detail="stream error")

        except Exception as exc:
            tb = traceback.format_exc()
            logger.error(f"XHTTP[stream-up] [{session_id[:8]}] stream CRASHED: {type(exc).__name__}: {exc}\n{tb}")
            error_logs.append({"error": f"stream-up crash: {type(exc).__name__}: {exc}", "time": datetime.now().isoformat()})
            await gate.flush()
            await _teardown(session_id, reason=f"crash: {type(exc).__name__}")
            raise HTTPException(status_code=502, detail="stream error")

        await gate.flush()
        return {"ok": True}
