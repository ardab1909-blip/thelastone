"""Billing: iyzico Checkout Form (card + 3DS hosted by iyzico) with stored-card monthly renewals.
PRO = ₺149/ay. First charge via hosted form (registerCard), renewals charged server-side from the stored card."""
import os
import re
import json
import html
import uuid
import asyncio
import logging
import calendar
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import iyzipay
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import PlainTextResponse, HTMLResponse
from pydantic import BaseModel, Field, field_validator

from auth import get_current_user, public_user
from pii import encrypt_pii, decrypt_pii, is_masked, mask_identity, mask_phone, protect

logger = logging.getLogger(__name__)
db = None

API_KEY = os.environ.get("IYZICO_API_KEY", "")
SECRET = os.environ.get("IYZICO_SECRET_KEY", "")
MERCHANT_ID = os.environ.get("IYZICO_MERCHANT_ID", "")
BASE = os.environ.get("IYZICO_BASE_URL", "https://sandbox-api.iyzipay.com").rstrip("/")
OPTIONS = {"api_key": API_KEY, "secret_key": SECRET, "base_url": BASE.replace("https://", "")}

# iyzico'nun 3DS sonrası tarayıcıyı yönlendireceği herkese açık backend adresi (Render adresin)
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://thelastone-07fj.onrender.com").rstrip("/")

PLAN = {"name": "WEIRD STUDIO PRO — Aylık", "price": 149.0, "currency": "TRY", "symbol": "₺"}
RENEW_CHECK_SECONDS = 3600
GRACE_DAYS = 3


def configure(database):
    global db
    db = database


def configured() -> bool:
    return bool(API_KEY and SECRET and MERCHANT_ID)


def now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now().isoformat()


def add_month(dt: datetime) -> datetime:
    month = dt.month % 12 + 1
    year = dt.year + (1 if dt.month == 12 else 0)
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------- iyzico SDK (sync) wrapped for the event loop ----------
async def iyzi(resource, method: str, payload: dict) -> Dict[str, Any]:
    if not configured():
        raise HTTPException(503, "Ödeme sağlayıcısı yapılandırılmadı")

    def call():
        r = getattr(resource(), method)(payload, OPTIONS)
        return json.loads(r.read().decode("utf-8"))

    try:
        data = await asyncio.to_thread(call)
    except Exception as e:
        logger.error("iyzico request failed: %s", e)
        raise HTTPException(502, "Ödeme sağlayıcısına ulaşılamadı")
    if data.get("status") != "success":
        logger.error("iyzico %s.%s failed: %s", resource.__name__, method, {k: data.get(k) for k in ("errorCode", "errorMessage", "errorGroup")})
        raise HTTPException(402 if data.get("errorGroup") else 502, data.get("errorMessage") or "Ödeme sağlayıcısı hatası")
    return data


# ---------- Schemas ----------
class BillingProfile(BaseModel):
    name: str = Field(min_length=2, max_length=40)
    surname: str = Field(min_length=2, max_length=40)
    # Telefon ve TC, uygulama tarafından maskeli (ör. *******8901) geri gönderilebilir; bu durumda kayıtlı değer korunur.
    gsm_number: str = Field(min_length=10, max_length=16)
    identity_number: str = Field(min_length=11, max_length=11)
    address: str = Field(min_length=5, max_length=160)
    city: str = Field(min_length=2, max_length=40)
    zip_code: str = Field(default="", max_length=10)

    @field_validator("gsm_number")
    @classmethod
    def _check_gsm(cls, v: str) -> str:
        pattern = r"\+?[\d*]{10,15}" if is_masked(v) else r"\+?\d{10,15}"
        if not re.fullmatch(pattern, v):
            raise ValueError("Geçersiz telefon numarası")
        return v

    @field_validator("identity_number")
    @classmethod
    def _check_identity(cls, v: str) -> str:
        pattern = r"[\d*]{11}" if is_masked(v) else r"\d{11}"
        if not re.fullmatch(pattern, v):
            raise ValueError("Geçersiz TC kimlik numarası")
        return v


class CheckoutIn(BaseModel):
    origin_url: str = Field(default="", max_length=200)


router = APIRouter(prefix="/billing", tags=["billing"])


def _safe_decrypt(value: str) -> str:
    try:
        return decrypt_pii(value or "")
    except RuntimeError as e:
        logger.error("PII çözülemedi: %s", e)
        return ""


def _public_profile(p: Dict[str, Any]) -> Dict[str, Any]:
    """İstemciye dönen profilde TC ve telefon maskelidir."""
    out = dict(p)
    if out.get("identity_number"):
        out["identity_number"] = mask_identity(_safe_decrypt(out["identity_number"]))
    if out.get("gsm_number"):
        out["gsm_number"] = mask_phone(_safe_decrypt(out["gsm_number"]))
    return out


async def _active_sub(user_id: str) -> Optional[Dict[str, Any]]:
    return await db.subscriptions.find_one({"user_id": user_id, "status": {"$in": ["ACTIVE", "CANCELED", "PAYMENT_FAILED"]}}, {"_id": 0, "card_user_key": 0, "card_token": 0}, sort=[("started_at", -1)])


@router.get("/config")
async def config(user=Depends(get_current_user)):
    profile = await db.billing_profiles.find_one({"user_id": user["id"]}, {"_id": 0, "user_id": 0})
    return {
        "configured": configured(), "provider": "iyzico", "sandbox": "sandbox" in BASE,
        "plan": PLAN, "has_profile": bool(profile), "subscription": await _active_sub(user["id"]),
    }


@router.get("/profile")
async def get_profile(user=Depends(get_current_user)):
    profile = await db.billing_profiles.find_one({"user_id": user["id"]}, {"_id": 0, "user_id": 0, "updated_at": 0})
    return _public_profile(profile) if profile else {}


@router.put("/profile")
async def put_profile(payload: BillingProfile, user=Depends(get_current_user)):
    existing = await db.billing_profiles.find_one({"user_id": user["id"]}, {"_id": 0}) or {}
    data = payload.model_dump()
    try:
        # Maskeli değer geldiyse eski kayıt korunur; yeni değer geldiyse şifrelenir
        data["identity_number"] = encrypt_pii(protect(payload.identity_number, existing.get("identity_number", "")))
        data["gsm_number"] = encrypt_pii(protect(payload.gsm_number, existing.get("gsm_number", "")))
    except RuntimeError as e:
        logger.error("PII şifreleme hatası: %s", e)
        raise HTTPException(503, "Sunucu yapılandırması eksik, daha sonra tekrar dene")
    if not data["identity_number"] or not data["gsm_number"]:
        raise HTTPException(400, "Telefon ve TC kimlik no gerekli")
    await db.billing_profiles.update_one({"user_id": user["id"]}, {"$set": {"user_id": user["id"], **data, "updated_at": now_iso()}}, upsert=True)
    return _public_profile(data)


def _buyer(user: Dict[str, Any], profile: Dict[str, Any], ip: str) -> Dict[str, Any]:
    # decrypt_pii, eski (düz metin) kayıtları olduğu gibi döndürür
    return {
        "id": user["id"], "name": profile["name"], "surname": profile["surname"], "gsmNumber": decrypt_pii(profile["gsm_number"]),
        "email": user["email"], "identityNumber": decrypt_pii(profile["identity_number"]), "registrationAddress": profile["address"],
        "ip": ip or "85.34.78.112", "city": profile["city"], "country": "Turkey", "zipCode": profile.get("zip_code") or "",
    }


def _address(profile: Dict[str, Any]) -> Dict[str, Any]:
    return {"contactName": f"{profile['name']} {profile['surname']}", "city": profile["city"], "country": "Turkey",
            "address": profile["address"], "zipCode": profile.get("zip_code") or ""}


def _basket(basket_id: str) -> Dict[str, Any]:
    price = f"{PLAN['price']:.1f}"
    return {"price": price, "paidPrice": price, "currency": PLAN["currency"], "basketId": basket_id, "paymentGroup": "SUBSCRIPTION",
            "basketItems": [{"id": "PRO_MONTHLY", "name": PLAN["name"], "category1": "Software", "itemType": "VIRTUAL", "price": price}]}


@router.post("/checkout")
async def checkout(payload: CheckoutIn, request: Request, user=Depends(get_current_user)):
    if user.get("is_pro"):
        raise HTTPException(400, "Hesabınız zaten PRO")
    if not configured():
        raise HTTPException(503, "Ödeme sağlayıcısı yapılandırılmadı. iyzico anahtarları eklenmeli.")
    profile = await db.billing_profiles.find_one({"user_id": user["id"]}, {"_id": 0})
    if not profile:
        raise HTTPException(400, "Önce fatura bilgilerini kaydet")
    conversation = str(uuid.uuid4())
    origin = payload.origin_url.rstrip("/")
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "")
    try:
        buyer = _buyer(user, profile, ip)
    except RuntimeError as e:
        logger.error("PII çözülemedi: %s", e)
        raise HTTPException(503, "Sunucu yapılandırması eksik, daha sonra tekrar dene")
    body = {
        "locale": "tr", "conversationId": conversation, "callbackUrl": f"{PUBLIC_BASE_URL}/api/billing/iyzico/callback",
        "enabledInstallments": ["1"], "registerCard": "1",
        "buyer": buyer, "billingAddress": _address(profile), "shippingAddress": _address(profile),
        **_basket(f"PRO-{conversation[:8]}"),
    }
    out = await iyzi(iyzipay.CheckoutFormInitialize, "create", body)
    await db.checkouts.insert_one({
        "id": str(uuid.uuid4()), "user_id": user["id"], "conversation_id": conversation, "token": out["token"],
        "origin_url": origin, "status": "started", "created_at": now_iso(),
    })
    return {"token": out["token"], "checkout_form_content": out["checkoutFormContent"], "payment_page_url": out.get("paymentPageUrl")}


async def _activate(user_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Idempotently records the first successful payment as an ACTIVE monthly subscription."""
    payment_id = str(result.get("paymentId"))
    existing = await db.subscriptions.find_one({"first_payment_id": payment_id}, {"_id": 0})
    if existing:
        return existing
    start = now()
    sub = {
        "id": str(uuid.uuid4()), "user_id": user_id, "first_payment_id": payment_id, "status": "ACTIVE",
        "card_user_key": result.get("cardUserKey"), "card_token": result.get("cardToken"),
        "card_last4": result.get("lastFourDigits"), "card_association": result.get("cardAssociation"),
        "amount": PLAN["price"], "currency": PLAN["currency"], "started_at": start.isoformat(),
        "renews_at": add_month(start).isoformat(), "cancel_at_period_end": False,
        "invoice_no": f"WS-{start.strftime('%Y%m%d')}-{payment_id[-6:].upper()}",
        "orders": [{"payment_id": payment_id, "at": start.isoformat(), "amount": PLAN["price"], "status": "success"}],
        "updated_at": start.isoformat(),
    }
    await db.subscriptions.update_many({"user_id": user_id, "status": {"$in": ["ACTIVE", "CANCELED", "PAYMENT_FAILED"]}}, {"$set": {"status": "REPLACED", "updated_at": now_iso()}})
    await db.subscriptions.insert_one(sub)
    await db.users.update_one({"id": user_id}, {"$set": {"is_pro": True, "plan": "pro_iyzico", "pro_since": start.isoformat(), "subscription_id": sub["id"]}})
    sub.pop("_id", None)
    return sub


async def _finalize_token(token: str) -> Dict[str, Any]:
    checkout = await db.checkouts.find_one({"token": token}, {"_id": 0})
    if not checkout:
        raise HTTPException(404, "Ödeme oturumu bulunamadı")
    if checkout["status"] in ("completed", "failed"):
        return checkout
    # Gerçek sonuç her zaman iyzico'dan token ile sorgulanır; istekteki hiçbir şeye güvenilmez
    result = await iyzi(iyzipay.CheckoutForm, "retrieve", {"locale": "tr", "token": token})
    payment_status = result.get("paymentStatus")
    if payment_status != "SUCCESS":
        # Sadece kesin başarısızlıkta "failed" işaretlenir; ödeme sürüyorsa oturum açık kalır
        if payment_status == "FAILURE":
            await db.checkouts.update_one({"token": token}, {"$set": {"status": "failed", "error": result.get("errorMessage"), "updated_at": now_iso()}})
        raise HTTPException(402, result.get("errorMessage") or "Ödeme tamamlanmadı")
    sub = await _activate(checkout["user_id"], result)
    await db.checkouts.update_one({"token": token}, {"$set": {"status": "completed", "subscription_id": sub["id"], "updated_at": now_iso()}})
    checkout.update({"status": "completed", "subscription_id": sub["id"]})
    return checkout


def _result_page(ok: bool) -> HTMLResponse:
    """3DS sonrası tarayıcıda gösterilen basit sayfa. Uygulama durumu kendi sorgular (/billing/status/{token})."""
    title = "Ödeme başarılı" if ok else "Ödeme tamamlanamadı"
    text = ("PRO üyeliğin etkinleştirildi. Bu pencereyi kapatıp Weird Studio uygulamasına dönebilirsin."
            if ok else "Ödeme doğrulanamadı. Uygulamaya dönüp tekrar deneyebilirsin.")
    page = (
        "<!doctype html><html lang='tr'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<style>body{font-family:system-ui,sans-serif;background:#0b0b12;color:#fff;display:flex;"
        "align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}"
        "div{max-width:420px;padding:24px}h1{font-size:22px}p{color:#aab}</style></head><body><div>"
        f"<h1>{'✅' if ok else '⚠️'} {html.escape(title)}</h1><p>{html.escape(text)}</p></div></body></html>"
    )
    return HTMLResponse(page)


@router.post("/iyzico/callback", response_class=HTMLResponse)
async def iyzico_callback(request: Request):
    # Eskiden token'ı doğrulamadan kullanıcıyı PRO yapıyordu (herkes bedava PRO alabilirdi).
    # Artık ödeme iyzico'dan sorgulanıp doğrulanır (_finalize_token).
    token = None
    try:
        form = await request.form()
        token = form.get("token")
    except Exception as e:
        logger.error("Callback form okunamadı: %s", e)
    if not token or not isinstance(token, str):
        return _result_page(False)
    try:
        checkout = await _finalize_token(token)
        return _result_page(checkout["status"] == "completed")
    except HTTPException:
        return _result_page(False)
    except Exception as e:
        logger.error("Callback hatası: %s", e)
        return _result_page(False)


@router.post("/iyzico/webhook")
async def iyzico_webhook(request: Request):
    # Payload is only a hint; the truth is fetched from iyzico by token (no trust in the body).
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    token = payload.get("token")
    if token and await db.checkouts.find_one({"token": token}):
        try:
            await _finalize_token(token)
        except HTTPException:
            pass
    return {"ok": True}


@router.get("/status/{token}")
async def status(token: str, user=Depends(get_current_user)):
    checkout = await db.checkouts.find_one({"token": token, "user_id": user["id"]}, {"_id": 0})
    if not checkout:
        raise HTTPException(404, "Ödeme oturumu bulunamadı")
    if checkout["status"] == "started":
        try:
            checkout = await _finalize_token(token)
        except HTTPException:
            checkout = await db.checkouts.find_one({"token": token}, {"_id": 0})
    fresh = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    sub = await db.subscriptions.find_one({"id": checkout.get("subscription_id")}, {"_id": 0, "card_user_key": 0, "card_token": 0}) if checkout.get("subscription_id") else None
    return {"status": checkout["status"], "error": checkout.get("error"), "subscription": sub, "user": public_user(fresh)}


@router.post("/cancel")
async def cancel(user=Depends(get_current_user)):
    sub = await db.subscriptions.find_one({"user_id": user["id"], "status": "ACTIVE"}, {"_id": 0})
    if not sub:
        if user.get("is_pro"):
            await db.users.update_one({"id": user["id"]}, {"$set": {"is_pro": False, "plan": "free"}, "$unset": {"pro_since": "", "subscription_id": ""}})
            user.update({"is_pro": False, "plan": "free", "pro_since": None})
            return {"user": public_user(user), "access_until": None}
        raise HTTPException(400, "Aktif PRO aboneliği yok")
    await db.subscriptions.update_one({"id": sub["id"]}, {"$set": {"status": "CANCELED", "cancel_at_period_end": True, "cancelled_at": now_iso(), "updated_at": now_iso()}})
    return {"user": public_user(user), "access_until": sub["renews_at"]}


@router.get("/history")
async def history(user=Depends(get_current_user)):
    return await db.subscriptions.find({"user_id": user["id"]}, {"_id": 0, "card_user_key": 0, "card_token": 0}).sort("started_at", -1).to_list(50)


def _invoice_text(user: Dict[str, Any], sub: Dict[str, Any]) -> str:
    orders = sub.get("orders", [])
    lines = [
        "==============================================",
        "        WEIRD STUDIO · STREAM DECK PRO",
        "                 FATURA / INVOICE",
        "==============================================",
        f"Fatura No     : {sub.get('invoice_no', '-')}",
        f"Başlangıç     : {sub.get('started_at', '')[:19].replace('T', ' ')} UTC",
        f"Müşteri       : {user.get('display_name') or user['email']}",
        f"E-posta       : {user['email']}",
        "----------------------------------------------",
        f"Ürün          : {PLAN['name']}",
        "Dönem         : Aylık (otomatik yenilenir)",
        f"Kart          : **** **** **** {sub.get('card_last4', '****')} ({sub.get('card_association', '-')})",
        f"Tutar         : {PLAN['symbol']}{sub.get('amount', PLAN['price']):.2f} {sub.get('currency', PLAN['currency'])}",
        f"Durum         : {sub.get('status', '-')}",
        f"Sonraki ödeme : {sub.get('renews_at', '')[:10] if sub.get('status') == 'ACTIVE' else '-'}",
        f"Sağlayıcı     : iyzico{' (sandbox)' if 'sandbox' in BASE else ''}",
        "----------------------------------------------",
        "Ödemeler:",
    ] + [f"  {o['at'][:10]}  {PLAN['symbol']}{o['amount']:.2f}  {o['status'].upper()}  #{o['payment_id']}" for o in orders] + [
        "----------------------------------------------",
        "Teşekkürler — WEIRD STUDIO",
        "==============================================",
    ]
    return "\n".join(lines)


@router.get("/invoice/{sub_id}", response_class=PlainTextResponse)
async def invoice(sub_id: str, user=Depends(get_current_user)):
    sub = await db.subscriptions.find_one({"id": sub_id, "user_id": user["id"]}, {"_id": 0})
    if not sub:
        raise HTTPException(404, "Fatura bulunamadı")
    return PlainTextResponse(_invoice_text(user, sub), headers={"Content-Disposition": "attachment; filename=WEIRD-STUDIO-INVOICE.txt"})


# ---------- Monthly renewals (stored card, server-side) ----------
async def renew_subscription(sub: Dict[str, Any]) -> bool:
    user = await db.users.find_one({"id": sub["user_id"]}, {"_id": 0})
    profile = await db.billing_profiles.find_one({"user_id": sub["user_id"]}, {"_id": 0})
    if not user or not profile or not sub.get("card_user_key"):
        return False
    try:
        buyer = _buyer(user, profile, "")
    except RuntimeError as e:
        logger.error("Yenileme atlandı, PII çözülemedi (%s): %s", sub["id"], e)
        return False
    conversation = str(uuid.uuid4())
    body = {
        "locale": "tr", "conversationId": conversation, "installment": "1",
        "paymentCard": {"cardUserKey": sub["card_user_key"], "cardToken": sub["card_token"]},
        "buyer": buyer, "billingAddress": _address(profile), "shippingAddress": _address(profile),
        **_basket(f"RENEW-{conversation[:8]}"),
    }
    try:
        result = await iyzi(iyzipay.Payment, "create", body)
        ok = result.get("paymentStatus") in (None, "SUCCESS")
        payment_id = str(result.get("paymentId", ""))
    except HTTPException as e:
        ok, payment_id = False, str(e.detail)
    order = {"payment_id": payment_id, "at": now_iso(), "amount": PLAN["price"], "status": "success" if ok else "failure"}
    if ok:
        renews = add_month(parse_iso(sub["renews_at"]))
        await db.subscriptions.update_one({"id": sub["id"]}, {"$set": {"status": "ACTIVE", "renews_at": renews.isoformat(), "updated_at": now_iso()}, "$push": {"orders": order}})
        await db.users.update_one({"id": sub["user_id"]}, {"$set": {"is_pro": True, "plan": "pro_iyzico"}})
    else:
        await db.subscriptions.update_one({"id": sub["id"]}, {"$set": {"status": "PAYMENT_FAILED", "updated_at": now_iso()}, "$push": {"orders": order}})
        await db.users.update_one({"id": sub["user_id"]}, {"$set": {"is_pro": False, "plan": "free"}})
    logger.info("Renewal for %s: %s", sub["id"], order["status"])
    return ok


async def run_renewals_once() -> Dict[str, int]:
    due = now().isoformat()
    stats = {"renewed": 0, "failed": 0, "expired": 0}
    if configured():
        async for sub in db.subscriptions.find({"status": "ACTIVE", "renews_at": {"$lte": due}}, {"_id": 0}):
            stats["renewed" if await renew_subscription(sub) else "failed"] += 1
    async for sub in db.subscriptions.find({"status": {"$in": ["CANCELED", "PAYMENT_FAILED"]}, "renews_at": {"$lte": due}}, {"_id": 0}):
        user = await db.users.find_one({"id": sub["user_id"], "is_pro": True, "subscription_id": sub["id"]})
        if user:
            await db.users.update_one({"id": sub["user_id"]}, {"$set": {"is_pro": False, "plan": "free"}, "$unset": {"pro_since": "", "subscription_id": ""}})
            stats["expired"] += 1
        if sub["status"] == "CANCELED":
            await db.subscriptions.update_one({"id": sub["id"]}, {"$set": {"status": "ENDED", "updated_at": now_iso()}})
    return stats


async def renewal_loop():
    while True:
        try:
            stats = await run_renewals_once()
            if any(stats.values()):
                logger.info("Renewal run: %s", stats)
        except Exception as e:
            logger.error("Renewal loop error: %s", e)
        await asyncio.sleep(RENEW_CHECK_SECONDS)
