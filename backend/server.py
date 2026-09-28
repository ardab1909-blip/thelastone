"""WEIRD STUDIO · Stream Deck Pro & Soundpad — Backend
FastAPI + MongoDB: JWT auth with OTP, per-user deck profiles, settings, uploads, mocked PRO billing."""
from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
import asyncio
import re
import uuid
import logging
import mimetypes
from datetime import datetime, timezone
from typing import List, Optional, Any, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException, Response, Depends
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, ConfigDict
from fastapi.staticfiles import StaticFiles

from storage import put_object, get_object, init_storage, APP_NAME
import auth
import billing
from auth import get_current_user

# ---------- Database & Logging ----------
mongo_url = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
db_name = os.environ.get("DB_NAME", "weirdstudio")

client = AsyncIOMotorClient(mongo_url)
db = client[db_name]

# ---------- Lifecycle (Lifespan) ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id", unique=True)
    await db.otp_codes.create_index("expires_at", expireAfterSeconds=0)
    await db.login_attempts.create_index("identifier")
    await db.profiles.create_index([("user_id", 1), ("created_at", 1)])
    await db.settings.create_index("user_id", unique=True)
    await db.subscriptions.create_index("id", unique=True)
    await db.subscriptions.create_index([("user_id", 1), ("status", 1)])
    await db.subscriptions.create_index([("status", 1), ("renews_at", 1)])
    await db.checkouts.create_index("token", unique=True)
    await db.billing_profiles.create_index("user_id", unique=True)
    
    
    asyncio.create_task(billing.renewal_loop())
    try:
        init_storage()
        logger.info("Object storage initialized")
    except Exception as e:
        logger.error(f"Object storage init failed: {e}")
    
    yield
    
    # Shutdown
    client.close()

# ---------- App Initialization ----------
app = FastAPI(title="WEIRD STUDIO Stream Deck Pro API", lifespan=lifespan)
UPLOAD_DIR = ROOT_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

# CORS middleware rotalardan ÖNCE eklenmeli
cors_origins = os.environ.get("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins if cors_origins != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# 1. uploads klasörünü tam yol ile otomatik oluştur
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 2. Yüklenen dosyaların taranabilmesi için statik klasör olarak dışa aç
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

api_router = APIRouter(prefix="/api")

# ---------- Config ----------
ALLOWED_AUDIO_EXTS = {".mp3", ".wav", ".ogg", ".webm", ".m4a"}
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

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

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
    trigger: str = Field(default="click", pattern="^(click|hold|key|toggle)$")
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
    count = await db.profiles.count_documents({"user_id": user_id})
    if count:
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

# ---------- Routes ----------
@api_router.get("/")
async def root():
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
    p = DeckProfile(user_id=user["id"], name=payload.name.strip(), tiles=_default_tiles(payload.name))
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
            for i in range(FREE_TILE_LIMIT, TILE_COUNT):
                if new_tiles[i] != Tile(**existing["tiles"][i]).model_dump():
                    raise HTTPException(403, "Kilitli tuşlar PRO üyelik gerektirir")
        updates["tiles"] = new_tiles
    await db.profiles.update_one({"id": pid}, {"$set": updates})
    return await _get_profile(pid, user["id"])

@api_router.patch("/profiles/{pid}/tiles/{index}")
async def update_tile(pid: str, index: int, payload: TileUpdate, user=Depends(get_current_user)):
    if not 0 <= index < TILE_COUNT:
        raise HTTPException(400, "Geçersiz tuş")
    if index >= FREE_TILE_LIMIT and not user.get("is_pro"):
        raise HTTPException(403, "Bu tuş PRO üyelik gerektirir")
    profile = await _get_profile(pid, user["id"])
    tiles = profile["tiles"]
    current = Tile(**tiles[index])
    merged = current.model_copy(update=payload.model_dump(exclude_none=True))
    merged.index = index
    tiles[index] = merged.model_dump()
    await db.profiles.update_one({"id": pid}, {"$set": {"tiles": tiles, "updated_at": now_iso()}})
    return tiles[index]

@api_router.delete("/profiles/{pid}")
async def delete_profile(pid: str, user=Depends(get_current_user)):
    await _get_profile(pid, user["id"])
    if await db.profiles.count_documents({"user_id": user["id"]}) <= 1:
        raise HTTPException(400, "Son profil silinemez")
    await db.profiles.delete_one({"id": pid})
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

@api_router.get("/settings")
async def get_settings(user=Depends(get_current_user)):
    await ensure_default_profiles(user["id"])
    doc = await db.settings.find_one({"user_id": user["id"]}, {"_id": 0})
    return UserSettings(**(doc or {})).model_dump()

@api_router.put("/settings")
async def put_settings(payload: UserSettingsUpdate, user=Depends(get_current_user)):
    doc = await db.settings.find_one({"user_id": user["id"]}, {"_id": 0}) or {}
    current = UserSettings(**doc)
    merged = current.model_copy(update=payload.model_dump(exclude_none=True))
    await db.settings.update_one({"user_id": user["id"]}, {"$set": {"user_id": user["id"], **merged.model_dump()}}, upsert=True)
    return merged.model_dump()

# ---------- Uploads ----------
@api_router.post("/upload/audio")
async def upload_audio(file: UploadFile = File(...)):
    try:
        # Dosya uzantısını güvenli şekilde al
        file_ext = os.path.splitext(file.filename)[1] or ".mp3"
        safe_name = f"{uuid.uuid4().hex}{file_ext}"
        
        # 'str / str' hatasını önlemek için os.path.join kullanıyoruz
        file_path = os.path.join(UPLOAD_DIR, safe_name)

        # Dosyayı lokal backend/uploads klasörüne kaydet
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)

        file_url = f"http://localhost:8000/uploads/{safe_name}"

        return {
            "id": safe_name,
            "filename": safe_name,
            "original_filename": file.filename,
            "display_name": file.filename,
            "url": file_url,
            "content_type": file.content_type
        }
    except Exception as e:
        logger.error(f"Lokal yükleme hatası: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/uploads")
async def list_uploads(user=Depends(get_current_user)):
    docs = await db.files.find({"user_id": user["id"], "is_deleted": False},
                               {"_id": 0, "storage_path": 0}).sort("created_at", -1).to_list(200)
    profiles = await db.profiles.find({"user_id": user["id"]}, {"_id": 0, "name": 1, "tiles.index": 1, "tiles.sound_url": 1}).to_list(200)
    for d in docs:
        d["url"] = f"/api/uploads/{d['id']}"
        d["display_name"] = d.get("display_name") or d["original_filename"]
        d["used_by"] = [{"profile": p["name"], "index": t["index"]} for p in profiles for t in p["tiles"] if t.get("sound_url") == d["url"]]
    return docs

class UploadRename(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)

@api_router.patch("/uploads/{file_id}")
async def rename_upload(file_id: str, payload: UploadRename, user=Depends(get_current_user)):
    name = payload.display_name.strip()
    res = await db.files.update_one({"id": file_id, "user_id": user["id"], "is_deleted": False}, {"$set": {"display_name": name}})
    if not res.matched_count:
        raise HTTPException(404, "Dosya bulunamadı")
    await db.profiles.update_many({"user_id": user["id"]}, {"$set": {"tiles.$[t].sound_name": name}},
                                  array_filters=[{"t.sound_url": f"/api/uploads/{file_id}"}])
    return {"id": file_id, "display_name": name}

@api_router.get("/uploads/{file_id}")
async def get_upload(file_id: str):
    if not re.fullmatch(r"[0-9a-f]{32}", file_id):
        raise HTTPException(404, "Dosya bulunamadı")
    record = await db.files.find_one({"id": file_id, "is_deleted": False}, {"_id": 0})
    if not record:
        raise HTTPException(404, "Dosya bulunamadı")
    try:
        data, content_type = get_object(record["storage_path"])
    except Exception as e:
        logger.error(f"Storage fetch failed: {e}")
        raise HTTPException(404, "Dosya bulunamadı") from e
    return Response(content=data, media_type=record.get("content_type", content_type),
                    headers={"Cache-Control": "private, max-age=3600"})

@api_router.delete("/uploads/{file_id}")
async def delete_upload(file_id: str, user=Depends(get_current_user)):
    res = await db.files.update_one({"id": file_id, "user_id": user["id"]}, {"$set": {"is_deleted": True}})
    if not res.matched_count:
        raise HTTPException(404, "Dosya bulunamadı")
    cleared = {"sound_type": "none", "sound_url": "", "sound_name": "", "sound_key": ""}
    await db.profiles.update_many({"user_id": user["id"]}, {"$set": {f"tiles.$[t].{k}": v for k, v in cleared.items()}},
                                  array_filters=[{"t.sound_url": f"/api/uploads/{file_id}"}])
    return {"deleted": True}

# ---------- Sub-routers Registration ----------
api_router.include_router(auth.router)
api_router.include_router(billing.router)

# ---------- Main App Router Inclusion ----------
app.include_router(api_router)
