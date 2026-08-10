# xhttshadpacketup.py
# XHTTP Shadowsocks — آپلود در مد packet-up (هر POST یک شماره‌ی seq داره؛
# چون ممکنه POSTها به‌ترتیب نرسن، بایت‌های خام seq-buffer میشن و فقط وقتی
# نوبت‌شون برسه وارد stream مشترک AEAD این session میشن — این برای حفظ
# ترتیب صحیح nonce حیاتیه).

import time
import traceback
from datetime import datetime

from fastapi import APIRouter, Request, HTTPException
from starlette.requests import ClientDisconnect

from main import stats, connections, error_logs, logger
from protocol.vless.vless import check_and_use
from protocol.shadowsocks.ss_xhttp_core import (
    ensure_reaper,
    check_link,
    get_or_create_session,
    teardown,
    feed_and_relay,
    PACKET_UP_HIGH_WATER,
    req_client_ip,
)

router = APIRouter()


@router.post("/xhttp-ss/packet-up/{uuid}/{session_id}/{seq}")
async def ss_packet_up_upload(uuid: str, session_id: str, seq: int, request: Request):
    ensure_reaper()
    link = await check_link(uuid)
    sess = await get_or_create_session(uuid, "packet-up", session_id, link, req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    sess["last_seen"] = time.time()
    try:
        body = await request.body()
    except ClientDisconnect:
        logger.info(f"SS-XHTTP[packet-up] [{session_id[:8]}] client disconnected mid-body (seq={seq}), session kept alive")
        return {"ok": True, "aborted": True}

    if not body:
        return {"ok": True}

    if not await check_and_use(uuid, len(body)):
        await teardown(session_id, reason="quota/disabled/unknown")
        raise HTTPException(status_code=403, detail="quota/disabled/unknown")

    stats["total_requests"] += 1
    connections[sess["conn_id"]]["bytes"] += len(body)

    async with sess["upload_lock"]:
        try:
            if seq == sess["next_seq"]:
                await feed_and_relay(session_id, uuid, sess, body)
                sess["next_seq"] += 1
                while sess["next_seq"] in sess["seq_buf"]:
                    pending = sess["seq_buf"].pop(sess["next_seq"])
                    await feed_and_relay(session_id, uuid, sess, pending)
                    sess["next_seq"] += 1
            else:
                sess["seq_buf"][seq] = body

            if sess["writer"] is not None and sess["writer"].transport.get_write_buffer_size() > PACKET_UP_HIGH_WATER:
                await sess["writer"].drain()
        except Exception as exc:
            tb = traceback.format_exc()
            logger.error(f"SS-XHTTP[packet-up] [{session_id[:8]}] upload FAILED seq={seq}: {type(exc).__name__}: {exc}\n{tb}")
            error_logs.append({"error": f"ss packet-up write failed: {type(exc).__name__}: {exc}", "time": datetime.now().isoformat()})
            await teardown(session_id, reason=f"write-failed: {type(exc).__name__}")
            raise HTTPException(status_code=502, detail="write failed")

    return {"ok": True, "connected": sess["writer"] is not None}
