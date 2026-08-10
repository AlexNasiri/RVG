# xhttpstreamon.py
# ══════════════════════════════════════════════════════════════════════════════
# XHTTP — دانلینک (GET) مشترک بین دو مد packet-up / stream-up
# معادل xhttshadstron.py در پوشه‌ی shadowsocks، اما برای VLESS / Trojan.
# منطق اصلی (session, quota, adaptive flow) در xhttp_core.py قرار دارد.
# ══════════════════════════════════════════════════════════════════════════════

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse

from protocol.vless.xhttp_core import (
    DEFAULT_FINGERPRINT,
    ensure_reaper,
    _check_link,
    _get_or_create_session,
    _req_client_ip,
    _resp_headers,
    _downstream_gen,
)

router = APIRouter()


# ══════════════════════════════ GET دانلینک (مشترک بین دو مد) ══════════════════════════════
@router.get("/xhttp-siz10/{mode}/{uuid}/{session_id}")
async def xhttp_downlink(mode: str, uuid: str, session_id: str, request: Request):
    ensure_reaper()
    if mode not in ("packet-up", "stream-up"):
        raise HTTPException(status_code=404, detail="unknown mode")
    await _check_link(uuid)
    fp = request.query_params.get("fp", DEFAULT_FINGERPRINT)
    sess = await _get_or_create_session(uuid, mode, session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    headers = _resp_headers(fp)
    return StreamingResponse(_downstream_gen(sess), headers=headers, media_type=headers["content-type"])
