# xhttpstreamone.py
# ══════════════════════════════════════════════════════════════════════════════
# XHTTP · ULTRA (mode=stream-one) — یک POST واحد که همزمان uplink (request body)
# و downlink (response body) رو روی همون کانکشن حمل می‌کنه (duplex واقعی، بدون
# session جدا برای GET). تاخیر کمتر از packet-up/stream-up چون نیازی به باز
# کردن دو HTTP request جدا (یکی GET یکی POST) نیست.
# منطق مشترک (session/quota/adaptive-flow) از xhttp_core.py استفاده می‌شه.
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
from protocol.vless.xhttp_core import (
    DEFAULT_FINGERPRINT,
    _AdaptiveFlow,
    _QuotaGate,
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


async def _uplink_pump(session_id: str, uuid: str, sess: dict, request: Request, gate: "_QuotaGate", flow: "_AdaptiveFlow"):
    close_reason = "uplink-eof"
    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            sess["last_seen"] = time.time()

            if not await gate.add(len(chunk)):
                close_reason = "quota-exceeded"
                logger.warning(f"XHTTP[stream-one] [{session_id[:8]}] quota exceeded during upload")
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
        logger.error(f"XHTTP[stream-one] [{session_id[:8]}] uplink pump crashed: {type(exc).__name__}: {exc}\n{tb}")
        error_logs.append({"error": f"stream-one uplink crash: {type(exc).__name__}: {exc}", "time": datetime.now().isoformat()})
    finally:
        await gate.flush()
        # وقتی uplink تموم شد یعنی کلاینت دیگه چیزی نمی‌فرسته؛ اما ممکنه downlink
        # هنوز درحال ارسال داده‌ی باقیمونده باشه، پس فقط وقتی TCP واقعاً بسته/خراب
        # شده کل session رو می‌بندیم، نه با هر بسته شدن ساده‌ی درخواست.
        if close_reason in ("remote-closing",) or close_reason.startswith("unexpected"):
            await _teardown(session_id, reason=close_reason)


# ══════════════════════════════ STREAM-ONE (یک POST duplex) ══════════════════════════════
# نکته‌ی مهم که از لاگ سرور تایید شد: کلاینت xray-core برای مود stream-one هیچ
# session_id ای به مسیر اضافه نمی‌کنه (چون این مود یعنی «یک درخواست = یک session
# کامل»، پس نیازی به شناسه‌ی مشترک بین چند درخواست نیست). درخواست واقعی که سرور
# می‌بینه دقیقاً همینه: POST /xhttp-siz10/stream-one/{uuid}  (با یا بدون / انتهایی)
# پس session_id رو خودمون داخل سرور می‌سازیم، نه از URL.
@router.post("/xhttp-siz10/stream-one/{uuid}")
@router.post("/xhttp-siz10/stream-one/{uuid}/")
async def xhttp_stream_one(uuid: str, request: Request):
    ensure_reaper()
    await _check_link(uuid)
    fp = request.query_params.get("fp", DEFAULT_FINGERPRINT)
    session_id = secrets.token_urlsafe(12)
    sess = await _get_or_create_session(uuid, "stream-one", session_id, _req_client_ip(request))
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

    sess["uplink_task"] = asyncio.create_task(
        _uplink_pump(session_id, uuid, sess, request, gate, flow)
    )

    headers = _resp_headers(fp)
    return StreamingResponse(_downstream_gen(sess), headers=headers, media_type=headers["content-type"])
