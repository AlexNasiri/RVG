# xhttpstreamone.py (trojan)
# ══════════════════════════════════════════════════════════════════════════════
# XHTTP · ULTRA (mode=stream-one) اختصاصی Trojan — یک POST واحد duplex.
# مستقل از موتور VLESS، مسیر با پیشوند /txhttp-siz10.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import secrets
import time
import traceback
from datetime import datetime

from fastapi import APIRouter, Request, HTTPException
from starlette.requests import ClientDisconnect
from fastapi.responses import StreamingResponse

from main import stats, connections, error_logs, logger
from protocol.trojan.xhttp_core import (
    TROJAN_DEFAULT_FINGERPRINT,
    _TrojanAdaptiveFlow,
    _TrojanQuotaGate,
    ensure_reaper,
    _check_link,
    _get_or_create_session,
    _open_tcp_for_session,
    _req_client_ip,
    _resp_headers,
    _downstream_gen,
    _teardown,
)

router = APIRouter()


async def _uplink_pump(session_id: str, uuid: str, sess: dict, request: Request, gate: "_TrojanQuotaGate", flow: "_TrojanAdaptiveFlow"):
    close_reason = "uplink-eof"
    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            sess["last_seen"] = time.time()

            if not await gate.add(len(chunk)):
                close_reason = "quota-exceeded"
                logger.warning(f"Trojan-XHTTP[stream-one] [{session_id[:8]}] quota exceeded during upload")
                break

            stats["total_requests"] += 1
            conn = connections.get(sess["conn_id"])
            if conn is not None:
                conn["bytes"] += len(chunk)

            writer = sess.get("writer")
            if writer is None:
                await _open_tcp_for_session(session_id, uuid, sess, chunk)
                continue

            if writer.is_closing():
                close_reason = "remote-closing"
                break
            writer.write(chunk)
            if flow.should_drain(writer.transport.get_write_buffer_size()):
                await flow.drain(writer)
    except ClientDisconnect:
        close_reason = "client-disconnected"
    except asyncio.CancelledError:
        close_reason = "cancelled"
        raise
    except Exception as exc:
        tb = traceback.format_exc()
        close_reason = f"unexpected: {type(exc).__name__}: {exc}"
        logger.error(f"Trojan-XHTTP[stream-one] [{session_id[:8]}] uplink pump crashed: {type(exc).__name__}: {exc}\n{tb}")
        error_logs.append({"error": f"trojan stream-one uplink crash: {type(exc).__name__}: {exc}", "time": datetime.now().isoformat()})
    finally:
        await gate.flush()
        if close_reason in ("remote-closing",) or close_reason.startswith("unexpected"):
            await _teardown(session_id, reason=close_reason)


@router.post("/txhttp-siz10/stream-one/{uuid}")
@router.post("/txhttp-siz10/stream-one/{uuid}/")
async def trojan_xhttp_stream_one(uuid: str, request: Request):
    ensure_reaper()
    await _check_link(uuid)
    fp = request.query_params.get("fp", TROJAN_DEFAULT_FINGERPRINT)
    session_id = secrets.token_urlsafe(12)
    sess = await _get_or_create_session(uuid, "stream-one", session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    gate = sess.get("gate")
    if gate is None:
        gate = _TrojanQuotaGate(uuid)
        sess["gate"] = gate
    flow = sess.get("flow")
    if flow is None:
        flow = _TrojanAdaptiveFlow()
        sess["flow"] = flow

    sess["uplink_task"] = asyncio.create_task(
        _uplink_pump(session_id, uuid, sess, request, gate, flow)
    )

    headers = _resp_headers(fp)
    return StreamingResponse(_downstream_gen(sess), headers=headers, media_type=headers["content-type"])
