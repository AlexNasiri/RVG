# xhttpstreamon.py (trojan)
# ══════════════════════════════════════════════════════════════════════════════
# XHTTP — دانلینک (GET) اختصاصی Trojan، مستقل از VLESS.
# مسیر با پیشوند /txhttp-siz10 تا با روت‌های VLESS (/xhttp-siz10) تداخل نداشته
# باشه و FastAPI بدون ابهام درخواست‌ها رو به موتور درست Trojan بفرسته.
# ══════════════════════════════════════════════════════════════════════════════

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse

from protocol.trojan.xhttp_core import (
    TROJAN_DEFAULT_FINGERPRINT,
    ensure_reaper,
    _check_link,
    _get_or_create_session,
    _req_client_ip,
    _resp_headers,
    _downstream_gen,
)

router = APIRouter()


# ══════════════════════════════ GET دانلینک (مشترک بین packet-up / stream-up) ══════════════════════════════
@router.get("/txhttp-siz10/{mode}/{uuid}/{session_id}")
async def trojan_xhttp_downlink(mode: str, uuid: str, session_id: str, request: Request):
    ensure_reaper()
    if mode not in ("packet-up", "stream-up"):
        raise HTTPException(status_code=404, detail="unknown mode")
    await _check_link(uuid)
    fp = request.query_params.get("fp", TROJAN_DEFAULT_FINGERPRINT)
    sess = await _get_or_create_session(uuid, mode, session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    headers = _resp_headers(fp)
    return StreamingResponse(_downstream_gen(sess), headers=headers, media_type=headers["content-type"])
