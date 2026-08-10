# xhttshadstron.py
# XHTTP Shadowsocks — دانلینک (stream-down: سرور → کلاینت) مشترک بین هر دو مد
# آپلود (packet-up و stream-up). کلاینت این مسیر رو با یک GET پایدار باز نگه
# می‌داره و سرور از طریق StreamingResponse فریم‌های AEAD-encrypted رو پشت‌سرهم
# push می‌کنه.

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse

from protocol.shadowsocks.ss_xhttp_core import (
    ensure_reaper,
    check_link,
    get_or_create_session,
    resp_headers,
    downstream_gen,
    DEFAULT_FINGERPRINT,
    req_client_ip,
)

router = APIRouter()


@router.get("/xhttp-ss/{mode}/{uuid}/{session_id}")
async def ss_xhttp_downlink(mode: str, uuid: str, session_id: str, request: Request):
    ensure_reaper()
    if mode not in ("packet-up", "stream-up"):
        raise HTTPException(status_code=404, detail="unknown mode")
    link = await check_link(uuid)
    fp = request.query_params.get("fp", DEFAULT_FINGERPRINT)
    sess = await get_or_create_session(uuid, mode, session_id, link, req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    headers = resp_headers(fp)
    return StreamingResponse(downstream_gen(sess), headers=headers, media_type=headers["content-type"])
