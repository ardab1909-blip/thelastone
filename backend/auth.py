"""Auth: email/password + 6-digit OTP verification, JWT bearer tokens, password reset.

Render ortam değişkenleri:
  JWT_SECRET     (ZORUNLU, uzun rastgele bir değer; ör. `python -c "import secrets;print(secrets.token_urlsafe(64))"`)
  OTP_DEV_MODE   (canlıda tanımlama ya da false bırak; true ise OTP kodu API yanıtında döner!)
"""

import os
import re
import time
import uuid
import hmac
import secrets
import hashlib
import logging

from datetime import datetime, timezone, timedelta
from typing import Dict, Any

import bcrypt
import jwt

from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel, Field, EmailStr
from pymongo import ReturnDocument

import emailer


logger = logging.getLogger(__name__)


JWT_ALGORITHM = "HS256"
OTP_TTL_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_SECONDS = 60
LOCK_MAX_FAILS = 5
LOCK_MINUTES = 15

_INSECURE_DEFAULT_SECRET = "super-secret-key-change-in-production"
JWT_SECRET = os.environ.get("JWT_SECRET", "")
if not JWT_SECRET or JWT_SECRET == _INSECURE_DEFAULT_SECRET:
    # Repo herkese açık olduğu için eski varsayılan değer bilinen bir sırdır; asla kullanılmaz.
    # Geçici rastgele anahtar güvenlidir ama her yeniden başlatmada herkes oturumdan düşer.
    logger.critical("JWT_SECRET tanımlı değil! Geçici rastgele anahtar kullanılıyor. Render'da JWT_SECRET ayarla.")
    JWT_SECRET = secrets.token_urlsafe(64)


db = None
# injected from server.py
on_verified = None
# async callback(user_id) injected from server.py


def configure(database, verified_hook=None):
    global db, on_verified
    db = database
    on_verified = verified_hook


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def otp_dev_mode() -> bool:
    return os.environ.get("OTP_DEV_MODE", "false").lower() == "true"


# ---------- Hashing ----------

def _pw_bytes(password: str) -> bytes:
    # bcrypt 72 baytın ötesini kabul etmez (yeni sürümler hata verir); hem hash hem doğrulamada aynı kesim uygulanır
    return password.encode("utf-8")[:72]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_pw_bytes(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_pw_bytes(plain), hashed.encode("utf-8"))
    except Exception:
        return False


def hash_code(code: str) -> str:
    return hashlib.sha256(f"{code}:{JWT_SECRET}".encode()).hexdigest()


def gen_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


# ---------- JWT ----------

def create_access_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "type": "access",
        "iat": int(time.time()),
        "exp": now_utc() + timedelta(days=7),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def public_user(user: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": user["id"],
        "email": user["email"],
        "display_name": user.get("display_name") or user["email"].split("@")[0],
        "is_verified": bool(user.get("is_verified")),
        "is_pro": bool(user.get("is_pro")),
        "plan": user.get("plan", "free"),
        "pro_since": user.get("pro_since"),
        "created_at": user.get("created_at"),
    }


async def get_current_user(request: Request) -> Dict[str, Any]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(401, "Oturum bulunamadı")

    token = auth_header[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Oturum süresi doldu")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Geçersiz oturum")

    if payload.get("type") != "access":
        raise HTTPException(401, "Geçersiz oturum")

    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0})
    if not user:
        raise HTTPException(401, "Kullanıcı bulunamadı")

    # Şifre sıfırlandıktan önce verilmiş tüm oturumlar geçersizdir
    if int(payload.get("iat", 0)) < int(user.get("token_valid_after") or 0):
        raise HTTPException(401, "Oturum geçersiz, tekrar giriş yap")

    if not user.get("is_verified"):
        raise HTTPException(403, "E-posta doğrulanmamış")

    return user


# ---------- OTP ----------

async def issue_otp(email: str, purpose: str) -> Dict[str, Any]:
    # Sürekli yeni kod isteyerek deneme hakkı sıfırlamayı ve e-posta bombardımanını engeller
    existing = await db.otp_codes.find_one({"email": email, "purpose": purpose}, {"created_at": 1})
    if existing and existing.get("created_at"):
        created = existing["created_at"]
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        wait = OTP_RESEND_SECONDS - (now_utc() - created).total_seconds()
        if wait > 0:
            raise HTTPException(429, f"Yeni kod için {int(wait) + 1} saniye bekle")

    code = gen_code()

    await db.otp_codes.delete_many({"email": email, "purpose": purpose})
    await db.otp_codes.insert_one({
        "id": str(uuid.uuid4()),
        "email": email,
        "purpose": purpose,
        "code_hash": hash_code(code),
        "attempts": 0,
        "expires_at": now_utc() + timedelta(minutes=OTP_TTL_MINUTES),
        "created_at": now_utc(),
    })

    sent = await emailer.send_otp(email, code, purpose)

    if not sent:
        if otp_dev_mode():
            logger.info("OTP [%s] for %s (email not delivered): %s", purpose, email, code)
        else:
            logger.warning("OTP e-postası gönderilemedi [%s] -> %s (SMTP ayarlarını kontrol et)", purpose, email)

    # Sadece OTP_DEV_MODE=true iken kod yanıtta da döner (gelen kutusu olmadan test için)
    return {"email_sent": sent, "dev_code": code if otp_dev_mode() else None}


async def consume_otp(email: str, purpose: str, code: str) -> None:
    # Deneme sayısı önce atomik olarak artırılır; paralel isteklerle sınır aşılamaz
    rec = await db.otp_codes.find_one_and_update(
        {"email": email, "purpose": purpose},
        {"$inc": {"attempts": 1}},
        return_document=ReturnDocument.AFTER,
    )

    if not rec:
        raise HTTPException(400, "Doğrulama kodu bulunamadı. Yeni kod isteyin.")

    expires = rec["expires_at"]
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    if expires < now_utc():
        await db.otp_codes.delete_one({"id": rec["id"]})
        raise HTTPException(400, "Kodun süresi doldu. Yeni kod isteyin.")

    if rec.get("attempts", 0) > OTP_MAX_ATTEMPTS:
        await db.otp_codes.delete_one({"id": rec["id"]})
        raise HTTPException(429, "Çok fazla hatalı deneme. Yeni kod isteyin.")

    if not hmac.compare_digest(rec["code_hash"], hash_code(code)):
        raise HTTPException(400, "Kod hatalı")

    await db.otp_codes.delete_one({"id": rec["id"]})


# ---------- Brute force ----------

async def check_lock(identifier: str):
    rec = await db.login_attempts.find_one({"identifier": identifier})

    if rec and rec.get("count", 0) >= LOCK_MAX_FAILS:
        locked_until = rec.get("locked_until")
        if locked_until and locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)

        if locked_until and locked_until > now_utc():
            raise HTTPException(429, "Çok fazla hatalı giriş. 15 dakika sonra tekrar deneyin.")

        await db.login_attempts.delete_one({"identifier": identifier})


async def record_fail(identifier: str):
    await db.login_attempts.update_one(
        {"identifier": identifier},
        {"$inc": {"count": 1}, "$set": {"locked_until": now_utc() + timedelta(minutes=LOCK_MINUTES)}},
        upsert=True,
    )


# ---------- Schemas ----------

class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)
    display_name: str = Field(default="", max_length=40)


class VerifyRequest(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6)


class EmailIn(BaseModel):
    email: EmailStr


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ResetIn(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6)
    new_password: str = Field(min_length=6, max_length=128)


class ProfileUpdateIn(BaseModel):
    display_name: str = Field(min_length=1, max_length=40)


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=6, max_length=128)


router = APIRouter(prefix="/auth", tags=["auth"])


# ---------- Register ----------

@router.post("/register")
async def register(payload: RegisterIn):
    email = payload.email.lower().strip()

    existing = await db.users.find_one({"email": email}, {"_id": 0})

    if existing and existing.get("is_verified"):
        raise HTTPException(409, "Bu e-posta zaten kayıtlı")

    user_id = existing["id"] if existing else str(uuid.uuid4())

    user = {
        "id": user_id,
        "email": email,
        "password_hash": hash_password(payload.password),
        "display_name": payload.display_name.strip() or email.split("@")[0],
        "is_verified": False,
        "is_pro": False,
        "plan": "free",
        "created_at": now_utc().isoformat(),
    }

    await db.users.replace_one({"email": email}, user, upsert=True)

    otp = await issue_otp(email, "verify")

    # Token doğrulanmamış hesap için verilir ama get_current_user e-posta doğrulanana kadar onu reddeder
    return {
        "message": "Doğrulama kodu gönderildi",
        "email": email,
        "token": create_access_token(user_id, email),
        "user": public_user(user),
        "needs_verification": True,
        **otp,
    }


# ---------- Resend code ----------

@router.post("/resend-code")
async def resend_code(payload: EmailIn):
    email = payload.email.lower().strip()

    user = await db.users.find_one({"email": email}, {"_id": 0})

    if not user or user.get("is_verified"):
        raise HTTPException(400, "Doğrulama bekleyen hesap bulunamadı")

    otp = await issue_otp(email, "verify")

    return {"message": "Yeni kod gönderildi", **otp}


# ---------- Verify ----------

@router.post("/verify")
async def verify(payload: VerifyRequest):
    email = payload.email.lower().strip()

    user = await db.users.find_one({"email": email}, {"_id": 0})

    if not user:
        raise HTTPException(400, "Doğrulama kodu bulunamadı. Yeni kod isteyin.")

    if user.get("is_verified"):
        raise HTTPException(400, "Hesap zaten doğrulanmış")

    # E-postaya gönderilen kod doğrulanmadan hesap asla aktif edilmez
    await consume_otp(email, "verify", payload.code)

    await db.users.update_one(
        {"email": email},
        {"$set": {"is_verified": True, "verified_at": now_utc().isoformat()}},
    )

    user["is_verified"] = True

    if on_verified:
        await on_verified(user["id"])

    token_value = create_access_token(user["id"], email)

    return {
        "access_token": token_value,
        "token": token_value,
        "accessToken": token_value,
        "jwt": token_value,
        "data": {"token": token_value, "access_token": token_value},
        "token_type": "bearer",
        "user": public_user(user),
    }


# ---------- Login ----------

@router.post("/login")
async def login(payload: LoginIn, request: Request):
    email = payload.email.lower().strip()

    ip = request.client.host if request.client else "?"
    identifier = f"{ip}:{email}"

    await check_lock(identifier)

    user = await db.users.find_one({"email": email}, {"_id": 0})

    if not user or not verify_password(payload.password, user["password_hash"]):
        await record_fail(identifier)
        raise HTTPException(401, "E-posta veya şifre hatalı")

    if not user.get("is_verified"):
        raise HTTPException(403, "E-posta doğrulanmamış")

    await db.login_attempts.delete_one({"identifier": identifier})

    return {
        "token": create_access_token(user["id"], email),
        "user": public_user(user),
    }


# ---------- Me ----------

@router.get("/me")
async def me(user=Depends(get_current_user)):
    return public_user(user)


# ---------- Update profile ----------

@router.patch("/me")
async def update_me(payload: ProfileUpdateIn, user=Depends(get_current_user)):
    name = payload.display_name.strip()

    await db.users.update_one({"id": user["id"]}, {"$set": {"display_name": name}})

    user["display_name"] = name

    return public_user(user)


# ---------- Change password ----------

@router.post("/change-password")
async def change_password(payload: PasswordChangeIn, user=Depends(get_current_user)):
    if not verify_password(payload.current_password, user["password_hash"]):
        raise HTTPException(400, "Mevcut şifre hatalı")

    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"password_hash": hash_password(payload.new_password)}},
    )

    return {"message": "Şifre güncellendi"}


# ---------- Forgot password ----------

@router.post("/forgot-password")
async def forgot_password(payload: EmailIn):
    email = payload.email.lower().strip()

    user = await db.users.find_one({"email": email}, {"_id": 0})

    otp = {"email_sent": False, "dev_code": None}

    if user:
        try:
            otp = await issue_otp(email, "reset")
        except HTTPException as e:
            if e.status_code != 429:
                raise
            # Bekleme süresi dolmadan tekrar isteyene de aynı genel yanıt verilir (hesap varlığı sızmaz)

    return {"message": "Hesap varsa sıfırlama kodu gönderildi", **otp}


# ---------- Reset password ----------

@router.post("/reset-password")
async def reset_password(payload: ResetIn):
    email = payload.email.lower().strip()

    user = await db.users.find_one({"email": email}, {"_id": 0})

    if not user:
        # Hesap yoksa da kod hatası ile aynı yanıt verilir
        raise HTTPException(400, "Doğrulama kodu bulunamadı. Yeni kod isteyin.")

    await consume_otp(email, "reset", payload.code)

    await db.users.update_one(
        {"email": email},
        {"$set": {
            "password_hash": hash_password(payload.new_password),
            "is_verified": True,
            "token_valid_after": int(time.time()),
        }},
    )

    await db.login_attempts.delete_many({"identifier": {"$regex": f":{re.escape(email)}$"}})

    return {"message": "Şifre sıfırlandı"}
