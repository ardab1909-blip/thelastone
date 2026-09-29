```python
"""WEIRD STUDIO · Authentication

Email/password authentication with:
- 6-digit OTP email verification
- JWT bearer tokens
- Password reset with OTP
- Brute-force login protection
- MongoDB persistence
"""

import os
import re
import uuid
import secrets
import hashlib
import logging

from datetime import datetime, timezone, timedelta
from typing import Dict, Any

import bcrypt
import jwt

from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel, Field, EmailStr

import emailer


logger = logging.getLogger(__name__)


# =========================================================
# CONFIG
# =========================================================

JWT_ALGORITHM = "HS256"

OTP_TTL_MINUTES = 10
OTP_MAX_ATTEMPTS = 5

LOCK_MAX_FAILS = 5
LOCK_MINUTES = 15


# MongoDB / callback injected from server.py
db = None
on_verified = None


def configure(database, verified_hook=None):
    """Initialize database and verification callback."""
    global db, on_verified

    db = database
    on_verified = verified_hook


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def otp_dev_mode() -> bool:
    """
    Development OTP mode.

    IMPORTANT:
    Keep OTP_DEV_MODE=false in production.
    """
    return os.environ.get("OTP_DEV_MODE", "false").lower() == "true"


# =========================================================
# JWT SECRET
# =========================================================

JWT_SECRET = os.environ.get("JWT_SECRET", "").strip()

if not JWT_SECRET:
    logger.warning(
        "JWT_SECRET environment variable is not configured. "
        "Set a strong random JWT_SECRET in production."
    )

    # Local development fallback only.
    JWT_SECRET = "dev-only-change-this-secret"


# =========================================================
# PASSWORD HASHING
# =========================================================

def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify bcrypt password hash."""
    try:
        return bcrypt.checkpw(
            plain.encode("utf-8"),
            hashed.encode("utf-8")
        )
    except Exception:
        return False


# =========================================================
# OTP
# =========================================================

def hash_code(code: str) -> str:
    """
    Hash OTP before storing it in MongoDB.

    The raw OTP is never stored in the database.
    """
    return hashlib.sha256(
        f"{code}:{JWT_SECRET}".encode("utf-8")
    ).hexdigest()


def gen_code() -> str:
    """Generate cryptographically secure 6-digit OTP."""
    return f"{secrets.randbelow(1_000_000):06d}"


async def issue_otp(email: str, purpose: str) -> Dict[str, Any]:
    """
    Create and send a new OTP.

    purpose:
        verify
        reset
    """

    code = gen_code()

    # Remove previous OTP for same purpose.
    await db.otp_codes.delete_many({
        "email": email,
        "purpose": purpose,
    })

    now = now_utc()

    await db.otp_codes.insert_one({
        "id": str(uuid.uuid4()),
        "email": email,
        "purpose": purpose,
        "code_hash": hash_code(code),
        "attempts": 0,
        "expires_at": now + timedelta(minutes=OTP_TTL_MINUTES),
        "created_at": now,
    })

    # Send email.
    sent = False

    try:
        sent = await emailer.send_otp(
            email,
            code,
            purpose
        )
    except Exception as exc:
        logger.error(
            "OTP email gönderilemedi: %s",
            exc,
            exc_info=True,
        )

    if not sent:
        logger.warning(
            "OTP e-posta ile gönderilemedi. "
            "purpose=%s email=%s",
            purpose,
            email,
        )

    # Only expose OTP during development.
    return {
        "email_sent": bool(sent),
        "dev_code": code if otp_dev_mode() else None,
    }


async def consume_otp(
    email: str,
    purpose: str,
    code: str,
) -> None:
    """
    Validate and consume an OTP.

    Raises:
        400 - invalid/expired OTP
        429 - too many attempts
    """

    code = str(code).strip()

    if not re.fullmatch(r"\d{6}", code):
        raise HTTPException(
            status_code=400,
            detail="Doğrulama kodu 6 haneli olmalıdır.",
        )

    record = await db.otp_codes.find_one({
        "email": email,
        "purpose": purpose,
    })

    if not record:
        raise HTTPException(
            status_code=400,
            detail="Doğrulama kodu bulunamadı. Yeni kod isteyin.",
        )

    expires = record.get("expires_at")

    if expires is None:
        await db.otp_codes.delete_one({
            "id": record["id"]
        })

        raise HTTPException(
            status_code=400,
            detail="Doğrulama kodu geçersiz.",
        )

    if expires.tzinfo is None:
        expires = expires.replace(
            tzinfo=timezone.utc
        )

    if expires < now_utc():
        await db.otp_codes.delete_one({
            "id": record["id"]
        })

        raise HTTPException(
            status_code=400,
            detail="Kodun süresi doldu. Yeni kod isteyin.",
        )

    attempts = int(
        record.get("attempts", 0)
    )

    if attempts >= OTP_MAX_ATTEMPTS:
        await db.otp_codes.delete_one({
            "id": record["id"]
        })

        raise HTTPException(
            status_code=429,
            detail="Çok fazla hatalı deneme. Yeni kod isteyin.",
        )

    expected_hash = record.get("code_hash")

    if not expected_hash or not secrets.compare_digest(
        expected_hash,
        hash_code(code),
    ):
        await db.otp_codes.update_one(
            {"id": record["id"]},
            {"$inc": {"attempts": 1}},
        )

        raise HTTPException(
            status_code=400,
            detail="Kod hatalı.",
        )

    # Correct OTP → consume it.
    await db.otp_codes.delete_one({
        "id": record["id"]
    })


# =========================================================
# JWT
# =========================================================

def create_access_token(
    user_id: str,
    email: str,
) -> str:
    """Create 7-day access token."""

    payload = {
        "sub": user_id,
        "email": email,
        "type": "access",
        "iat": now_utc(),
        "exp": now_utc() + timedelta(days=7),
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


# =========================================================
# PUBLIC USER
# =========================================================

def public_user(
    user: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Return only safe public user fields.

    password_hash is intentionally excluded.
    """

    email = user["email"]

    return {
        "id": user["id"],
        "email": email,
        "display_name": (
            user.get("display_name")
            or email.split("@")[0]
        ),
        "is_verified": bool(
            user.get("is_verified")
        ),
        "is_pro": bool(
            user.get("is_pro")
        ),
        "plan": user.get(
            "plan",
            "free",
        ),
        "pro_since": user.get(
            "pro_since"
        ),
        "created_at": user.get(
            "created_at"
        ),
    }


# =========================================================
# CURRENT USER
# =========================================================

async def get_current_user(
    request: Request,
) -> Dict[str, Any]:

    auth_header = request.headers.get(
        "Authorization",
        "",
    )

    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Oturum bulunamadı.",
        )

    token = auth_header[7:].strip()

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Oturum bulunamadı.",
        )

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Oturum süresi doldu.",
        )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Geçersiz oturum.",
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=401,
            detail="Geçersiz oturum.",
        )

    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Geçersiz oturum.",
        )

    user = await db.users.find_one(
        {"id": user_id},
        {"_id": 0},
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Kullanıcı bulunamadı.",
        )

    if not user.get("is_verified"):
        raise HTTPException(
            status_code=403,
            detail="E-posta doğrulanmamış.",
        )

    return user


# =========================================================
# BRUTE FORCE PROTECTION
# =========================================================

async def check_lock(
    identifier: str,
):
    record = await db.login_attempts.find_one({
        "identifier": identifier
    })

    if not record:
        return

    count = int(
        record.get("count", 0)
    )

    if count < LOCK_MAX_FAILS:
        return

    locked_until = record.get(
        "locked_until"
    )

    if locked_until and locked_until.tzinfo is None:
        locked_until = locked_until.replace(
            tzinfo=timezone.utc
        )

    if locked_until and locked_until > now_utc():
        raise HTTPException(
            status_code=429,
            detail=(
                "Çok fazla hatalı giriş. "
                "15 dakika sonra tekrar deneyin."
            ),
        )

    # Lock expired.
    await db.login_attempts.delete_one({
        "identifier": identifier
    })


async def record_fail(
    identifier: str,
):
    await db.login_attempts.update_one(
        {"identifier": identifier},
        {
            "$inc": {
                "count": 1
            },
            "$set": {
                "locked_until": (
                    now_utc()
                    + timedelta(
                        minutes=LOCK_MINUTES
                    )
                )
            },
        },
        upsert=True,
    )


# =========================================================
# SCHEMAS
# =========================================================

class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(
        min_length=6,
        max_length=128,
    )
    display_name: str = Field(
        default="",
        max_length=40,
    )


class VerifyRequest(BaseModel):
    email: EmailStr
    code: str = Field(
        min_length=6,
        max_length=6,
    )


class EmailIn(BaseModel):
    email: EmailStr


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ResetIn(BaseModel):
    email: EmailStr
    code: str = Field(
        min_length=6,
        max_length=6,
    )
    new_password: str = Field(
        min_length=6,
        max_length=128,
    )


class ProfileUpdateIn(BaseModel):
    display_name: str = Field(
        min_length=1,
        max_length=40,
    )


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str = Field(
        min_length=6,
        max_length=128,
    )


# =========================================================
# ROUTER
# =========================================================

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


# =========================================================
# REGISTER
# =========================================================

@router.post("/register")
async def register(
    payload: RegisterIn,
):
    email = str(
        payload.email
    ).lower().strip()

    display_name = (
        payload.display_name.strip()
    )

    existing = await db.users.find_one(
        {"email": email},
        {"_id": 0},
    )

    # Already verified.
    if existing and existing.get(
        "is_verified"
    ):
        raise HTTPException(
            status_code=409,
            detail="Bu e-posta zaten kayıtlı.",
        )

    # Existing but unverified:
    # update password/name and issue a fresh OTP.
    user_id = (
        existing["id"]
        if existing
        else str(uuid.uuid4())
    )

    user = {
        "id": user_id,
        "email": email,
        "password_hash": hash_password(
            payload.password
        ),
        "display_name": (
            display_name
            or email.split("@")[0]
        ),
        "is_verified": False,
        "is_pro": False,
        "plan": "free",
        "created_at": (
            existing.get("created_at")
            if existing
            else now_utc().isoformat()
        ),
    }

    await db.users.replace_one(
        {"email": email},
        user,
        upsert=True,
    )

    otp = await issue_otp(
        email,
        "verify",
    )

    return {
        "message": (
            "Doğrulama kodu gönderildi."
        ),
        "email": email,
        "needs_verification": True,
        **otp,
    }


# =========================================================
# RESEND VERIFICATION CODE
# =========================================================

@router.post("/resend-code")
async def resend_code(
    payload: EmailIn,
):
    email = str(
        payload.email
    ).lower().strip()

    user = await db.users.find_one(
        {"email": email},
        {"_id": 0},
    )

    if not user:
        raise HTTPException(
            status_code=400,
            detail=(
                "Doğrulama bekleyen hesap bulunamadı."
            ),
        )

    if user.get("is_verified"):
        raise HTTPException(
            status_code=400,
            detail="Bu hesap zaten doğrulanmış.",
        )

    otp = await issue_otp(
        email,
        "verify",
    )

    return {
        "message": "Yeni kod gönderildi.",
        **otp,
    }


# =========================================================
# VERIFY EMAIL
# =========================================================

@router.post("/verify")
async def verify(
    payload: VerifyRequest,
):
    email = str(
        payload.email
    ).lower().strip()

    user = await db.users.find_one(
        {"email": email},
        {"_id": 0},
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Hesap bulunamadı.",
        )

    if user.get("is_verified"):
        raise HTTPException(
            status_code=400,
            detail="Hesap zaten doğrulanmış.",
        )

    # =====================================================
    # IMPORTANT:
    # OTP IS ACTUALLY VERIFIED HERE.
    # =====================================================

    await consume_otp(
        email,
        "verify",
        payload.code,
    )

    verified_at = now_utc().isoformat()

    await db.users.update_one(
        {"email": email},
        {
            "$set": {
                "is_verified": True,
                "verified_at": verified_at,
            }
        },
    )

    user["is_verified"] = True
    user["verified_at"] = verified_at

    # Create default profiles/settings.
    if on_verified:
        try:
            await on_verified(
                user["id"]
            )
        except Exception as exc:
            logger.error(
                "on_verified callback failed: %s",
                exc,
                exc_info=True,
            )

    token = create_access_token(
        user["id"],
        email,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": public_user(user),
    }


# =========================================================
# LOGIN
# =========================================================

@router.post("/login")
async def login(
    payload: LoginIn,
    request: Request,
):
    email = str(
        payload.email
    ).lower().strip()

    ip = (
        request.client.host
        if request.client
        else "unknown"
    )

    identifier = f"{ip}:{email}"

    await check_lock(identifier)

    user = await db.users.find_one(
        {"email": email},
        {"_id": 0},
    )

    # Never reveal whether email exists.
    if (
        not user
        or not verify_password(
            payload.password,
            user.get(
                "password_hash",
                "",
            ),
        )
    ):
        await record_fail(
            identifier
        )

        raise HTTPException(
            status_code=401,
            detail="E-posta veya şifre hatalı.",
        )

    # =====================================================
    # UNVERIFIED USER
    # =====================================================

    if not user.get("is_verified"):
        otp = await issue_otp(
            email,
            "verify",
        )

        return {
            "needs_verification": True,
            "email": email,
            **otp,
        }

    # Successful login → clear failed attempts.
    await db.login_attempts.delete_one({
        "identifier": identifier
    })

    token = create_access_token(
        user["id"],
        email,
    )

    return {
        "token": token,
        "access_token": token,
        "token_type": "bearer",
        "user": public_user(user),
    }


# =========================================================
# CURRENT USER
# =========================================================

@router.get("/me")
async def me(
    user=Depends(get_current_user),
):
    return public_user(user)


# =========================================================
# UPDATE PROFILE
# =========================================================

@router.patch("/me")
async def update_me(
    payload: ProfileUpdateIn,
    user=Depends(get_current_user),
):
    display_name = (
        payload.display_name.strip()
    )

    await db.users.update_one(
        {"id": user["id"]},
        {
            "$set": {
                "display_name": display_name
            }
        },
    )

    user["display_name"] = display_name

    return public_user(user)


# =========================================================
# CHANGE PASSWORD
# =========================================================

@router.post("/change-password")
async def change_password(
    payload: PasswordChangeIn,
    user=Depends(get_current_user),
):
    if not verify_password(
        payload.current_password,
        user["password_hash"],
    ):
        raise HTTPException(
            status_code=400,
            detail="Mevcut şifre hatalı.",
        )

    await db.users.update_one(
        {"id": user["id"]},
        {
            "$set": {
                "password_hash": hash_password(
                    payload.new_password
                )
            }
        },
    )

    return {
        "message": "Şifre güncellendi."
    }


# =========================================================
# FORGOT PASSWORD
# =========================================================

@router.post("/forgot-password")
async def forgot_password(
    payload: EmailIn,
):
    email = str(
        payload.email
    ).lower().strip()

    user = await db.users.find_one(
        {"email": email},
        {"_id": 0},
    )

    # Do not reveal account existence.
    if not user:
        return {
            "message": (
                "Hesap varsa sıfırlama "
                "kodu gönderildi."
            ),
            "email_sent": False,
            "dev_code": None,
        }

    otp = await issue_otp(
        email,
        "reset",
    )

    return {
        "message": (
            "Hesap varsa sıfırlama "
            "kodu gönderildi."
        ),
        **otp,
    }


# =========================================================
# RESET PASSWORD
# =========================================================

@router.post("/reset-password")
async def reset_password(
    payload: ResetIn,
):
    email = str(
        payload.email
    ).lower().strip()

    user = await db.users.find_one(
        {"email": email},
        {"_id": 0},
    )

    # Keep response generic where possible.
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Geçersiz sıfırlama isteği.",
        )

    # =====================================================
    # ACTUALLY VERIFY RESET OTP
    # =====================================================

    await consume_otp(
        email,
        "reset",
        payload.code,
    )

    await db.users.update_one(
        {"email": email},
        {
            "$set": {
                "password_hash": hash_password(
                    payload.new_password
                ),
                "is_verified": True,
            }
        },
    )

    # Clear login lock for this email.
    await db.login_attempts.delete_many({
        "identifier": {
            "$regex": f":{re.escape(email)}$"
        }
    })

    return {
        "message": (
            "Şifre sıfırlandı."
        )
    }
```
