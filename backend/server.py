"""WEIRD STUDIO · Stream Deck Pro & Soundpad — Backend
FastAPI + MongoDB: JWT auth with OTP, per-user deck profiles, settings, uploads, mocked PRO billing."""
from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
import asyncio
import contextlib
import re
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional, Any, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException, Response, Depends
from fastapi.responses import FileResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, ConfigDict
from fastapi.staticfiles import StaticFiles

from storage import get_object, init_storage
import auth
import billing
import pii
from auth import get_current_user

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- Config (hepsi env'den; varsayılanlar eski davranışı korur) ----------
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.environ.get("DB_NAME", "weirdstudio")
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://thelastone-07fj.onrender.com").rstrip("/")
CORS_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]

AUDIO_CONTENT_TYPES = {
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".webm": "audio/webm",
    ".m4a": "audio/mp4",
}
MAX_AUDIO_SIZE = 15 * 1024 * 1024
TILE_COUNT = 15
FREE_TILE_LIMIT = 6
FREE_UPLOAD_LIMIT = 3
DEFAULT_PROFILE_NAMES = ["Streaming", "Gaming", "Podcast", "Production"]
SYNTH_PRESETS = [
    ("Airhorn", "MEME", "📣", "#ff007f", "airhorn"),
    ("Cyber Glitch", "FX", "⚡", "#00f2fe", "glitch"),
    ("8-Bit Coin", "GAME", "🪙", "#ffd60a", "coin"),
    ("Applause", "SHOW", "👏", "#00ff66", "applause"),
    ("Buzzer", "GAME", "🚨", "#ff3b3b", "buzzer"),
    ("Laser Shot", "FX", "🔫", "#b400ff", "laser"),
    ("Jingle", "MUSIC", "🎵", "#00f2fe", "jingle"),
]

UPLOAD_DIR = ROOT_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# ---------- Database ----------
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def create_indexes() -> None:
    """Index hatası uygulamanın açılmasını engellemesin."""
    specs = [
        (db.users, "email", {"unique": True}),
        (db.users, "id", {"unique": True}),
        (db.otp_codes, "expires_at", {"expireAfterSeconds": 0}),
        (db.login_attempts, "identifier", {}),
        (db.profiles, "id", {"unique": True}),
        (db.profiles, [("user_id", 1), ("created_at", 1)], {}),
        (db.settings, "user_id", {"unique": True}),
        (db.subscriptions, "id", {"unique": True}),
        (db.subscriptions, [("user_id", 1), ("status", 1)], {}),
        (db.subscriptions, [("status", 1), ("renews_at", 1)], {}),
        (db.checkouts, "token", {"unique": True}),
        (db.billing_profiles, "user_id", {"unique": True}),
        (db.files, "id", {"unique": True}),
        (db.files, [("user_id", 1), ("is_deleted", 1), ("created_at", -1)], {}),
    ]
    for coll, keys, opts in specs:
        try:
            await coll.create_index(keys, **opts)
        except Exception as e:
            logger.error(f"Index oluşturulamadı ({coll.name} {keys}): {e}")


# ---------- Lifespan ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_indexes()
    try:
        pii.check_config()
    except Exception as e:
        logger.error(f"PII_ENCRYPTION_KEY eksik ya da hatalı, fatura bilgileri kaydedilemez: {e}")
    renewal_task = asyncio.create_task(billing.renewal_loop())
    try:
        init_storage()
        logger.info("Object storage initialized")
    except Exception as e:
        logger.error(f"Object storage init failed: {e}")

    yield

    renewal_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await renewal_task
    client.close()


# ---------- App ----------
app = FastAPI(title="WEIRD STUDIO Stream Deck Pro API", lifespan=lifespan)


@app.get("/")
async def root():
    return {"app": "WEIRD STUDIO Stream Deck Pro", "status": "ok"}


if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    logger.warning("CORS_ORIGINS tanımlı değil: tüm originlere izin veriliyor (production için tanımla)")
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=".*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Eski yüklemelerin URL'leri (/uploads/<dosya>) çalışmaya devam etsin
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

api_router = APIRouter(prefix="/api")


# ---------- Models ----------
class Tile(BaseModel):
    model_config = ConfigDict(extra="ignore")
    index: int = Field(ge=0, lt=TILE_COUNT)
    label: str = Field(default="", max_length=40)
    subtitle: str = Field(default="", max_length=16)
    emoji: str = Field(default="", max_length=8)
    color: str = Field(default="#00f2fe", pattern=r"^#[0-9a-fA-F]{6}$")
    sound_type: str = Field(default="none", pattern=r"^(none|synth|file|recording)$")
    sound_key: str = Field(default="", max_length=32)
    sound_url: str = Field(default="", max_length=400)
    sound_name: str = Field(default="", max_length=120)
    trigger: str = Field(default="click", pattern="^(click|hold|key|toggle)$")
    shortcut: str = Field(default="", max_length=40)
    volume: float = Field(default=0.8, ge=0.0, le=1.0)


class DeckProfile(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    name: str = Field(max_length=40)
    tiles: List[Tile] = []
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)


class ProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=40)


class ProfileUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=40)
    tiles: Optional[List[Tile]] = None


class TileUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")
    label: Optional[str] = Field(default=None, max_length=40)
    subtitle: Optional[str] = Field(default=None, max_length=16)
    emoji: Optional[str] = Field(default=None, max_length=8)
    color: Optional[str] = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")
    sound_type: Optional[str] = Field(default=None, pattern=r"^(none|synth|file|recording)$")
    sound_key: Optional[str] = Field(default=None, max_length=32)
    sound_url: Optional[str] = Field(default=None, max_length=400)
    sound_name: Optional[str] = Field(default=None, max_length=120)
    # Önceden default="click" idi: her PATCH tuşun trigger'ını sessizce "click"e sıfırlıyordu.
    trigger: Optional[str] = Field(default=None, pattern="^(click|hold|key|toggle)$")
    shortcut: Optional[str] = Field(default=None, max_length=40)
    volume: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class MicSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")
    pitch: float = Field(default=1.0, ge=0.5, le=2.0)
    reverb: float = Field(default=0.0, ge=0.0, le=1.0)
    gain: float = Field(default=1.0, ge=0.0, le=1.5)
    preset: str = Field(default="none", max_length=24)


class UserSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")
    master_volume: float = Field(default=0.9, ge=0.0, le=1.0)
    active_profile_id: str = ""
    mic: MicSettings = MicSettings()


class UserSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")
    master_volume: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    active_profile_id: Optional[str] = None
    mic: Optional[MicSettings] = None


class UploadRename(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)


# ---------- Helpers ----------
def _default_tiles(profile_name: str) -> List[Tile]:
    tiles = []
    for i in range(TILE_COUNT):
        if i < len(SYNTH_PRESETS):
            label, sub, emoji, color, key = SYNTH_PRESETS[i]
            tiles.append(Tile(index=i, label=label, subtitle=sub, emoji=emoji, color=color,
                              sound_type="synth", sound_key=key, shortcut=f"Ctrl+Shift+{(i + 1) % 10}"))
        else:
            tiles.append(Tile(index=i, subtitle=profile_name.upper()[:8]))
    return tiles


async def ensure_default_profiles(user_id: str) -> None:
    if await db.profiles.count_documents({"user_id": user_id}, limit=1):
        return
    docs = [DeckProfile(user_id=user_id, name=n, tiles=_default_tiles(n)).model_dump() for n in DEFAULT_PROFILE_NAMES]
    await db.profiles.insert_many(docs)
    await db.settings.update_one(
        {"user_id": user_id},
        {"$set": {"user_id": user_id, **UserSettings(active_profile_id=docs[0]["id"]).model_dump()}},
        upsert=True,
    )


auth.configure(db, ensure_default_profiles)
billing.configure(db)


async def _get_profile(pid: str, user_id: str) -> Dict[str, Any]:
    p = await db.profiles.find_one({"id": pid, "user_id": user_id}, {"_id": 0})
    if not p:
        raise HTTPException(404, "Profil bulunamadı")
    return p


# ---------- Profile routes ----------
@api_router.get("/")
async def api_root():
    return {"app": "WEIRD STUDIO Stream Deck Pro", "status": "ok"}


@api_router.get("/profiles")
async def list_profiles(user=Depends(get_current_user)):
    await ensure_default_profiles(user["id"])
    return await db.profiles.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", 1).to_list(200)


@api_router.post("/profiles")
async def create_profile(payload: ProfileCreate, user=Depends(get_current_user)):
    if not user.get("is_pro"):
        count = await db.profiles.count_documents({"user_id": user["id"]})
        if count >= len(DEFAULT_PROFILE_NAMES):
            raise HTTPException(403, "Yeni profil oluşturmak için PRO gerekir")
    name = payload.name.strip()
    p = DeckProfile(user_id=user["id"], name=name, tiles=_default_tiles(name))
    await db.profiles.insert_one(p.model_dump())
    return p.model_dump()


@api_router.get("/profiles/{pid}")
async def get_profile(pid: str, user=Depends(get_current_user)):
    return await _get_profile(pid, user["id"])


@api_router.put("/profiles/{pid}")
async def update_profile(pid: str, payload: ProfileUpdate, user=Depends(get_current_user)):
    existing = await _get_profile(pid, user["id"])
    updates: Dict[str, Any] = {"updated_at": now_iso()}
    if payload.name is not None:
        updates["name"] = payload.name.strip()
    if payload.tiles is not None:
        if len(payload.tiles) != TILE_COUNT or sorted(t.index for t in payload.tiles) != list(range(TILE_COUNT)):
            raise HTTPException(400, f"Profil tam olarak {TILE_COUNT} tuş içermeli")
        new_tiles = [t.model_dump() for t in sorted(payload.tiles, key=lambda t: t.index)]
        if not user.get("is_pro"):
            old_tiles = existing.get("tiles", [])
            for i in range(FREE_TILE_LIMIT, TILE_COUNT):
                old = Tile(**old_tiles[i]).model_dump() if i < len(old_tiles) else Tile(index=i).model_dump()
                if new_tiles[i] != old:
                    raise HTTPException(403, "Kilitli tuşlar PRO üyelik gerektirir")
        updates["tiles"] = new_tiles
    await db.profiles.update_one({"id": pid, "user_id": user["id"]}, {"$set": updates})
    return await _get_profile(pid, user["id"])


@api_router.patch("/profiles/{pid}/tiles/{index}")
async def update_tile(pid: str, index: int, payload: TileUpdate, user=Depends(get_current_user)):
    if not 0 <= index < TILE_COUNT:
        raise HTTPException(400, "Geçersiz tuş")
    if index >= FREE_TILE_LIMIT and not user.get("is_pro"):
        raise HTTPException(403, "Bu tuş PRO üyelik gerektirir")
    profile = await _get_profile(pid, user["id"])
    tiles = profile.get("tiles", [])
    if index >= len(tiles):
        raise HTTPException(404, "Tuş bulunamadı")
    # Doğrulamalı birleştirme (model_copy(update=...) doğrulama yapmaz)
    merged = Tile(**{**Tile(**tiles[index]).model_dump(), **payload.model_dump(exclude_none=True), "index": index})
    tile_doc = merged.model_dump()
    # Tüm diziyi yeniden yazmak yerine sadece ilgili tuşu güncelle (eşzamanlı isteklerde veri kaybını önler)
    await db.profiles.update_one(
        {"id": pid, "user_id": user["id"]},
        {"$set": {f"tiles.{index}": tile_doc, "updated_at": now_iso()}},
    )
    return tile_doc


@api_router.delete("/profiles/{pid}")
async def delete_profile(pid: str, user=Depends(get_current_user)):
    await _get_profile(pid, user["id"])
    if await db.profiles.count_documents({"user_id": user["id"]}) <= 1:
        raise HTTPException(400, "Son profil silinemez")
    await db.profiles.delete_one({"id": pid, "user_id": user["id"]})
    # Aktif profil silindiyse ayarlar boşta kalmasın
    st = await db.settings.find_one({"user_id": user["id"]}, {"_id": 0})
    if st and st.get("active_profile_id") == pid:
        first = await db.profiles.find_one({"user_id": user["id"]}, {"_id": 0, "id": 1}, sort=[("created_at", 1)])
        await db.settings.update_one({"user_id": user["id"]},
                                     {"$set": {"active_profile_id": first["id"] if first else ""}})
    return {"deleted": True}


@api_router.post("/profiles/{pid}/duplicate")
async def duplicate_profile(pid: str, user=Depends(get_current_user)):
    if not user.get("is_pro"):
        raise HTTPException(403, "Profil kopyalamak için PRO gerekir")
    existing = await _get_profile(pid, user["id"])
    dup = DeckProfile(user_id=user["id"], name=f"{existing['name']} (kopya)"[:40],
                      tiles=[Tile(**t) for t in existing["tiles"]])
    await db.profiles.insert_one(dup.model_dump())
    return dup.model_dump()


# ---------- Settings routes ----------
@api_router.get("/settings")
async def get_settings(user=Depends(get_current_user)):
    await ensure_default_profiles(user["id"])
    doc = await db.settings.find_one({"user_id": user["id"]}, {"_id": 0})
    return UserSettings(**(doc or {})).model_dump()


@api_router.put("/settings")
async def put_settings(payload: UserSettingsUpdate, user=Depends(get_current_user)):
    doc = await db.settings.find_one({"user_id": user["id"]}, {"_id": 0}) or {}
    changes = payload.model_dump(exclude_none=True)
    if changes.get("active_profile_id"):
        await _get_profile(changes["active_profile_id"], user["id"])  # başkasının profiline işaret edemesin
    # İç içe `mic` dahil doğrulamalı birleştirme
    merged = UserSettings(**{**UserSettings(**doc).model_dump(), **changes})
    await db.settings.update_one({"user_id": user["id"]},
                                 {"$set": {"user_id": user["id"], **merged.model_dump()}}, upsert=True)
    return merged.model_dump()


# ---------- Uploads ----------
def _upload_url_matcher(file_id: str) -> Dict[str, Any]:
    """Tuşlarda URL hem göreli (/api/uploads/<id>) hem mutlak (https://.../api/uploads/<id>) saklanmış olabilir."""
    return {"$regex": f"/api/uploads/{file_id}$"}


async def _write_upload(file: UploadFile, dest: Path) -> int:
    """Dosyayı parça parça yazar; boyut sınırını aşarsa yarım dosyayı siler."""
    size = 0
    try:
        with open(dest, "wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_AUDIO_SIZE:
                    raise HTTPException(413, f"Dosya en fazla {MAX_AUDIO_SIZE // (1024 * 1024)} MB olabilir")
                out.write(chunk)
    except Exception:
        dest.unlink(missing_ok=True)
        raise
    return size


@api_router.post("/upload/audio")
async def upload_audio(file: UploadFile = File(...), user=Depends(get_current_user)):
    ext = Path(file.filename or "").suffix.lower()
    if ext not in AUDIO_CONTENT_TYPES:
        raise HTTPException(400, f"Desteklenen formatlar: {', '.join(sorted(AUDIO_CONTENT_TYPES))}")

    if not user.get("is_pro"):
        used = await db.files.count_documents({"user_id": user["id"], "is_deleted": False})
        if used >= FREE_UPLOAD_LIMIT:
            raise HTTPException(403, f"Ücretsiz planda en fazla {FREE_UPLOAD_LIMIT} ses yüklenebilir")

    file_id = uuid.uuid4().hex
    stored_name = f"{file_id}{ext}"
    try:
        size = await _write_upload(file, UPLOAD_DIR / stored_name)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Lokal yükleme hatası: {e}")
        raise HTTPException(500, "Dosya kaydedilemedi") from e

    await db.files.insert_one({
        "id": file_id,
        "user_id": user["id"],
        "original_filename": file.filename,
        "display_name": file.filename,
        "storage_backend": "local",
        "storage_path": stored_name,
        "content_type": AUDIO_CONTENT_TYPES[ext],
        "size": size,
        "is_deleted": False,
        "created_at": now_iso(),
    })
    return {
        "id": file_id,
        "filename": stored_name,
        "original_filename": file.filename,
        "display_name": file.filename,
        "url": f"{PUBLIC_BASE_URL}/api/uploads/{file_id}",
        "content_type": AUDIO_CONTENT_TYPES[ext],
    }


@api_router.get("/uploads")
async def list_uploads(user=Depends(get_current_user)):
    docs = await db.files.find({"user_id": user["id"], "is_deleted": False},
                               {"_id": 0, "storage_path": 0}).sort("created_at", -1).to_list(200)
    profiles = await db.profiles.find({"user_id": user["id"]},
                                      {"_id": 0, "name": 1, "tiles.index": 1, "tiles.sound_url": 1}).to_list(200)
    for d in docs:
        d["url"] = f"/api/uploads/{d['id']}"
        d["display_name"] = d.get("display_name") or d["original_filename"]
        d["used_by"] = [{"profile": p["name"], "index": t["index"]}
                        for p in profiles for t in p["tiles"]
                        if (t.get("sound_url") or "").endswith(d["url"])]
    return docs


@api_router.patch("/uploads/{file_id}")
async def rename_upload(file_id: str, payload: UploadRename, user=Depends(get_current_user)):
    if not re.fullmatch(r"[0-9a-f]{32}", file_id):
        raise HTTPException(404, "Dosya bulunamadı")
    name = payload.display_name.strip()
    res = await db.files.update_one({"id": file_id, "user_id": user["id"], "is_deleted": False},
                                    {"$set": {"display_name": name}})
    if not res.matched_count:
        raise HTTPException(404, "Dosya bulunamadı")
    await db.profiles.update_many({"user_id": user["id"]}, {"$set": {"tiles.$[t].sound_name": name}},
                                  array_filters=[{"t.sound_url": _upload_url_matcher(file_id)}])
    return {"id": file_id, "display_name": name}


@api_router.get("/uploads/{file_id}")
async def get_upload(file_id: str):
    if not re.fullmatch(r"[0-9a-f]{32}", file_id):
        raise HTTPException(404, "Dosya bulunamadı")
    record = await db.files.find_one({"id": file_id, "is_deleted": False}, {"_id": 0})
    if not record:
        raise HTTPException(404, "Dosya bulunamadı")

    cache = {"Cache-Control": "private, max-age=3600"}
    if record.get("storage_backend") == "local":
        path = UPLOAD_DIR / record["storage_path"]
        if not path.is_file():
            raise HTTPException(404, "Dosya bulunamadı")
        return FileResponse(path, media_type=record.get("content_type") or "application/octet-stream", headers=cache)

    # Eski kayıtlar: object storage
    try:
        data, content_type = get_object(record["storage_path"])
    except Exception as e:
        logger.error(f"Storage fetch failed: {e}")
        raise HTTPException(404, "Dosya bulunamadı") from e
    return Response(content=data, media_type=record.get("content_type", content_type), headers=cache)


@api_router.delete("/uploads/{file_id}")
async def delete_upload(file_id: str, user=Depends(get_current_user)):
    if not re.fullmatch(r"[0-9a-f]{32}", file_id):
        raise HTTPException(404, "Dosya bulunamadı")
    res = await db.files.update_one({"id": file_id, "user_id": user["id"]}, {"$set": {"is_deleted": True}})
    if not res.matched_count:
        raise HTTPException(404, "Dosya bulunamadı")
    cleared = {"sound_type": "none", "sound_url": "", "sound_name": "", "sound_key": ""}
    await db.profiles.update_many({"user_id": user["id"]},
                                  {"$set": {f"tiles.$[t].{k}": v for k, v in cleared.items()}},
                                  array_filters=[{"t.sound_url": _upload_url_matcher(file_id)}])
    return {"deleted": True}


# ---------- Sub-routers ----------
api_router.include_router(auth.router)
api_router.include_router(billing.router)

app.include_router(api_router)
