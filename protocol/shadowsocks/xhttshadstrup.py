# xhttshadstrup.py
# XHTTP Shadowsocks — آپلود در مد stream-up (یک یا چند POST پیوسته روی یک
# session؛ کلاینت مجاز است چند POST متوالی بفرسته — بستن یک POST به‌معنی
# قطع کل تونل نیست، فقط این درخواست تمام میشه).

import time
import traceback
from datetime import datetime

from fastapi import APIRouter, Request, HTTPException
from starlette.requests import ClientDisconnect

from main import stats, connections, error_logs, logger
from protocol.shadowsocks.ss_xhttp_core import (
    ensure_reaper,
    check_link,
    get_or_create_session,
    teardown,
    feed_and_relay,
    QuotaGate,
    AdaptiveFlow,
    req_client_ip,
)

router = APIRouter()


@router.post("/xhttp-ss/stream-up/{uuid}/{session_id}")
async def ss_stream_up_upload(uuid: str, session_id: str, request: Request):
    ensure_reaper()
    link = await check_link(uuid)
    sess = await get_or_create_session(uuid, "stream-up", session_id, link, req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    gate = sess.get("gate")
    if gate is None:
        gate = QuotaGate(uuid)
        sess["gate"] = gate

    flow = sess.get("flow")
    if flow is None:
        flow = AdaptiveFlow()
        sess["flow"] = flow

    conn = connections.get(sess["conn_id"])
    if conn is None:
        raise HTTPException(status_code=404, detail="session closed")

    async with sess["upload_lock"]:
        try:
            async for chunk in request.stream():
                if not chunk:
                    continue
                sess["last_seen"] = time.time()

                if not await gate.add(len(chunk)):
                    logger.warning(f"SS-XHTTP[stream-up] [{session_id[:8]}] quota exceeded during upload")
                    raise HTTPException(status_code=403, detail="quota/disabled/unknown")

                stats["total_requests"] += 1
                conn["bytes"] += len(chunk)

                await feed_and_relay(session_id, uuid, sess, chunk)

                if sess["writer"] is not None and flow.should_drain(sess["writer"].transport.get_write_buffer_size()):
                    await flow.drain(sess["writer"])

        except ClientDisconnect:
            # کلاینت uplink رو بست تا downlink ادامه بده؛ TCP/session زنده می‌مونه.
            await gate.flush()
            if sess.get("writer") and not sess["writer"].is_closing():
                try:
                    await sess["writer"].drain()
                except Exception:
                    pass
            logger.info(f"SS-XHTTP[stream-up] [{session_id[:8]}] uplink closed by client, downlink still active")
            return

        except HTTPException as exc:
            logger.warning(f"SS-XHTTP[stream-up] [{session_id[:8]}] HTTPException: {exc.status_code} {exc.detail}")
            await gate.flush()
            await teardown(session_id, reason=f"http-{exc.status_code}")
            raise

        except (ConnectionResetError, BrokenPipeError, ConnectionError) as exc:
            logger.warning(f"SS-XHTTP[stream-up] [{session_id[:8]}] connection error: {type(exc).__name__}: {exc}")
            error_logs.append({"error": f"ss stream-up conn error: {type(exc).__name__}: {exc}", "time": datetime.now().isoformat()})
            await gate.flush()
            await teardown(session_id, reason=f"conn-error: {type(exc).__name__}")
            raise HTTPException(status_code=502, detail="stream error")

        except Exception as exc:
            tb = traceback.format_exc()
            logger.error(f"SS-XHTTP[stream-up] [{session_id[:8]}] stream CRASHED: {type(exc).__name__}: {exc}\n{tb}")
            error_logs.append({"error": f"ss stream-up crash: {type(exc).__name__}: {exc}", "time": datetime.now().isoformat()})
            await gate.flush()
            await teardown(session_id, reason=f"crash: {type(exc).__name__}")
            raise HTTPException(status_code=502, detail="stream error")

        await gate.flush()
        return {"ok": True}
