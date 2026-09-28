"""WEIRD STUDIO Stream Deck Pro — comprehensive backend API tests (iyzico iteration)."""
import os
import io
import struct
import uuid
import wave
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    with open("/app/frontend/.env") as fh:
        for line in fh:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
                break
API = f"{BASE_URL}/api"


def _wav_bytes(seconds=0.1, rate=8000):
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(struct.pack("<" + "h" * int(rate * seconds), *([0] * int(rate * seconds))))
    return buf.getvalue()


def _unique_email(prefix="e2e_"):
    return f"{prefix}{uuid.uuid4().hex[:10]}@example.com"


@pytest.fixture(scope="session")
def s():
    return requests.Session()


def _headers(token):
    return {"Authorization": f"Bearer {token}"}


def _restore_demo_pro():
    """Restore demo user's PRO status directly via mongo (using backend/.env)."""
    import pymongo
    mongo_url, db_name = None, None
    for line in open("/app/backend/.env"):
        line = line.strip()
        if line.startswith("MONGO_URL="):
            mongo_url = line.split("=", 1)[1].strip().strip('"').strip("'")
        elif line.startswith("DB_NAME="):
            db_name = line.split("=", 1)[1].strip().strip('"').strip("'")
    cli = pymongo.MongoClient(mongo_url)
    cli[db_name].users.update_one({"email": "demo@weird.studio"},
                                  {"$set": {"is_pro": True, "plan": "pro_iyzico"}})
    cli.close()


def _register_and_verify(s, email=None, password="testpass123"):
    email = email or _unique_email()
    r = s.post(f"{API}/auth/register", json={"email": email, "password": password, "display_name": "T"})
    assert r.status_code == 200, r.text
    body = r.json()
    dev_code = body["dev_code"]
    assert dev_code and len(dev_code) == 6
    r = s.post(f"{API}/auth/verify", json={"email": email, "code": dev_code})
    assert r.status_code == 200, r.text
    data = r.json()
    return {"email": email, "password": password, "token": data["token"], "user": data["user"],
            "email_sent": body.get("email_sent")}


# ========== AUTH (OTP email) ==========
class TestAuth:
    def test_register_returns_email_sent_and_dev_code(self, s):
        email = _unique_email()
        r = s.post(f"{API}/auth/register", json={"email": email, "password": "pw123456"})
        assert r.status_code == 200
        body = r.json()
        assert "email_sent" in body
        assert isinstance(body["email_sent"], bool)
        assert body.get("dev_code") and len(body["dev_code"]) == 6
        # verify works
        r = s.post(f"{API}/auth/verify", json={"email": email, "code": body["dev_code"]})
        assert r.status_code == 200
        assert r.json()["user"]["is_verified"] is True

    def test_verify_wrong_code(self, s):
        email = _unique_email()
        s.post(f"{API}/auth/register", json={"email": email, "password": "pw123456"})
        r = s.post(f"{API}/auth/verify", json={"email": email, "code": "000000"})
        assert r.status_code == 400

    def test_login_success_and_wrong_password(self, s):
        u = _register_and_verify(s)
        r = s.post(f"{API}/auth/login", json={"email": u["email"], "password": u["password"]})
        assert r.status_code == 200 and "token" in r.json()
        r = s.post(f"{API}/auth/login", json={"email": u["email"], "password": "wrong123"})
        assert r.status_code == 401

    def test_me_requires_token(self, s):
        u = _register_and_verify(s)
        r = s.get(f"{API}/auth/me")
        assert r.status_code == 401
        r = s.get(f"{API}/auth/me", headers=_headers(u["token"]))
        assert r.status_code == 200 and r.json()["email"] == u["email"]

    def test_forgot_password_known_user_returns_dev_code(self, s):
        u = _register_and_verify(s)
        r = s.post(f"{API}/auth/forgot-password", json={"email": u["email"]})
        assert r.status_code == 200
        j = r.json()
        assert j["email_sent"] in (True, False)
        assert j["dev_code"] and len(j["dev_code"]) == 6

    def test_forgot_password_unknown_user_no_leak(self, s):
        r = s.post(f"{API}/auth/forgot-password", json={"email": f"nobody_{uuid.uuid4().hex[:6]}@example.com"})
        assert r.status_code == 200
        j = r.json()
        assert j["email_sent"] is False
        assert j["dev_code"] is None

    def test_forgot_then_reset(self, s):
        u = _register_and_verify(s)
        r = s.post(f"{API}/auth/forgot-password", json={"email": u["email"]})
        code = r.json()["dev_code"]
        r = s.post(f"{API}/auth/reset-password",
                   json={"email": u["email"], "code": code, "new_password": "newerpw22"})
        assert r.status_code == 200
        r = s.post(f"{API}/auth/login", json={"email": u["email"], "password": "newerpw22"})
        assert r.status_code == 200


# ========== PROFILES / SETTINGS / TILE SWAP ==========
class TestProfiles:
    def test_default_profiles(self, s):
        u = _register_and_verify(s)
        r = s.get(f"{API}/profiles", headers=_headers(u["token"]))
        assert r.status_code == 200
        profs = r.json()
        assert len(profs) == 4
        assert [p["name"] for p in profs] == ["Streaming", "Gaming", "Podcast", "Production"]
        for p in profs:
            assert len(p["tiles"]) == 15

    def test_patch_tile_free_gating(self, s):
        u = _register_and_verify(s)
        pid = s.get(f"{API}/profiles", headers=_headers(u["token"])).json()[0]["id"]
        r = s.patch(f"{API}/profiles/{pid}/tiles/2", json={"label": "Custom"}, headers=_headers(u["token"]))
        assert r.status_code == 200 and r.json()["label"] == "Custom"
        r = s.patch(f"{API}/profiles/{pid}/tiles/10", json={"label": "X"}, headers=_headers(u["token"]))
        assert r.status_code == 403

    def test_swap_tiles_within_free_range_ok(self, s):
        u = _register_and_verify(s)
        pid = s.get(f"{API}/profiles", headers=_headers(u["token"])).json()[0]["id"]
        prof = s.get(f"{API}/profiles/{pid}", headers=_headers(u["token"])).json()
        tiles = prof["tiles"]
        # swap contents of tile 0 and tile 2 (keep indices 0..14)
        a, b = dict(tiles[0]), dict(tiles[2])
        a["index"], b["index"] = 2, 0
        new_tiles = list(tiles)
        new_tiles[0] = b
        new_tiles[2] = a
        r = s.put(f"{API}/profiles/{pid}", json={"tiles": new_tiles}, headers=_headers(u["token"]))
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["tiles"][0]["label"] == tiles[2]["label"]
        assert j["tiles"][2]["label"] == tiles[0]["label"]

    def test_swap_locked_tile_forbidden_for_free(self, s):
        u = _register_and_verify(s)
        pid = s.get(f"{API}/profiles", headers=_headers(u["token"])).json()[0]["id"]
        prof = s.get(f"{API}/profiles/{pid}", headers=_headers(u["token"])).json()
        tiles = prof["tiles"]
        a, b = dict(tiles[0]), dict(tiles[8])
        a["index"], b["index"] = 8, 0
        new_tiles = list(tiles)
        new_tiles[0] = b
        new_tiles[8] = a
        r = s.put(f"{API}/profiles/{pid}", json={"tiles": new_tiles}, headers=_headers(u["token"]))
        assert r.status_code == 403

    def test_put_wrong_tile_count(self, s):
        u = _register_and_verify(s)
        pid = s.get(f"{API}/profiles", headers=_headers(u["token"])).json()[0]["id"]
        prof = s.get(f"{API}/profiles/{pid}", headers=_headers(u["token"])).json()
        r = s.put(f"{API}/profiles/{pid}", json={"tiles": prof["tiles"][:14]}, headers=_headers(u["token"]))
        assert r.status_code == 400

    def test_settings_get_put(self, s):
        u = _register_and_verify(s)
        r = s.put(f"{API}/settings", json={"master_volume": 0.55}, headers=_headers(u["token"]))
        assert r.status_code == 200
        assert s.get(f"{API}/settings", headers=_headers(u["token"])).json()["master_volume"] == 0.55


# ========== BILLING (iyzico) ==========
class TestBilling:
    def test_config_reports_provider(self, s):
        u = _register_and_verify(s)
        r = s.get(f"{API}/billing/config", headers=_headers(u["token"]))
        assert r.status_code == 200
        j = r.json()
        assert j["provider"] == "iyzico"
        assert isinstance(j["configured"], bool)
        assert j["plan"]["price"] == 149.0
        assert j["plan"]["currency"] == "TRY"
        assert isinstance(j["has_profile"], bool)
        assert j["has_profile"] is False

    def test_billing_profile_validation_identity(self, s):
        u = _register_and_verify(s)
        bad = {"name": "Al", "surname": "Ka", "gsm_number": "+905551112233",
               "identity_number": "12345", "address": "Sokak No 1 Kadikoy Istanbul",
               "city": "Istanbul", "zip_code": "34710"}
        r = s.put(f"{API}/billing/profile", json=bad, headers=_headers(u["token"]))
        assert r.status_code == 422

    def test_billing_profile_validation_gsm(self, s):
        u = _register_and_verify(s)
        bad = {"name": "Al", "surname": "Ka", "gsm_number": "abc123",
               "identity_number": "12345678901", "address": "Sokak No 1 Kadikoy Istanbul",
               "city": "Istanbul", "zip_code": "34710"}
        r = s.put(f"{API}/billing/profile", json=bad, headers=_headers(u["token"]))
        assert r.status_code == 422

    def test_billing_profile_save_and_get(self, s):
        u = _register_and_verify(s)
        good = {"name": "Ali", "surname": "Kaya", "gsm_number": "+905551112233",
                "identity_number": "12345678901", "address": "Bagdat Cad No 12",
                "city": "Istanbul", "zip_code": "34710"}
        r = s.put(f"{API}/billing/profile", json=good, headers=_headers(u["token"]))
        assert r.status_code == 200
        r = s.get(f"{API}/billing/profile", headers=_headers(u["token"]))
        assert r.status_code == 200
        assert r.json()["identity_number"] == "12345678901"
        # has_profile true now
        r = s.get(f"{API}/billing/config", headers=_headers(u["token"]))
        assert r.json()["has_profile"] is True

    def test_checkout_requires_profile(self, s):
        u = _register_and_verify(s)
        # Without a billing profile → 400 (or 503 if iyzico not configured)
        r = s.post(f"{API}/billing/checkout",
                   json={"origin_url": BASE_URL}, headers=_headers(u["token"]))
        assert r.status_code in (400, 503)

    def test_checkout_with_profile_returns_token_or_503(self, s):
        u = _register_and_verify(s)
        s.put(f"{API}/billing/profile", json={
            "name": "Ali", "surname": "Kaya", "gsm_number": "+905551112233",
            "identity_number": "12345678901", "address": "Bagdat Cad No 12",
            "city": "Istanbul", "zip_code": "34710"}, headers=_headers(u["token"]))
        r = s.post(f"{API}/billing/checkout",
                   json={"origin_url": BASE_URL}, headers=_headers(u["token"]))
        assert r.status_code in (200, 503, 502, 402)
        if r.status_code == 200:
            j = r.json()
            assert j.get("token")
            assert "<script" in (j.get("checkout_form_content") or "").lower() or j.get("payment_page_url")
            # status endpoint should not 404 for this token
            r2 = s.get(f"{API}/billing/status/{j['token']}", headers=_headers(u["token"]))
            assert r2.status_code == 200
            assert r2.json()["status"] in ("started", "completed", "failed")

    def test_status_unknown_token_404(self, s):
        u = _register_and_verify(s)
        r = s.get(f"{API}/billing/status/does-not-exist-xyz", headers=_headers(u["token"]))
        assert r.status_code == 404

    def test_webhook_accepts_and_returns_ok(self, s):
        # Current implementation logs+finalizes best-effort; returns 200 {ok:true}
        r = s.post(f"{API}/billing/iyzico/webhook",
                   json={"iyziEventType": "subscription.order.success", "token": "nonexistent"},
                   headers={"X-IYZ-SIGNATURE-V3": "bogus"})
        assert r.status_code == 200
        assert r.json().get("ok") is True

    def test_history_empty_list(self, s):
        u = _register_and_verify(s)
        r = s.get(f"{API}/billing/history", headers=_headers(u["token"]))
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_invoice_unknown_404(self, s):
        u = _register_and_verify(s)
        r = s.get(f"{API}/billing/invoice/bogus-sub-id", headers=_headers(u["token"]))
        assert r.status_code == 404

    def test_cancel_requires_pro(self, s):
        u = _register_and_verify(s)
        r = s.post(f"{API}/billing/cancel", headers=_headers(u["token"]))
        assert r.status_code == 400

    def test_demo_pro_cancel_then_restore(self, s):
        """Cancel demo user's PRO status, then restore. Handles both cases: with & without real active sub."""
        _restore_demo_pro()
        r = s.post(f"{API}/auth/login", json={"email": "demo@weird.studio", "password": "demo1234"})
        if r.status_code != 200:
            pytest.skip("demo user not seeded")
        demo = r.json()
        assert demo["user"]["is_pro"] is True
        r = s.post(f"{API}/billing/cancel", headers=_headers(demo["token"]))
        assert r.status_code == 200
        body = r.json()
        assert "user" in body
        # Either: had ACTIVE sub → is_pro still True + access_until set, or:
        #   no ACTIVE sub → is_pro flipped to False + access_until is None
        if body.get("access_until"):
            assert body["user"]["is_pro"] is True
        else:
            assert body["user"]["is_pro"] is False
        _restore_demo_pro()
        r = s.post(f"{API}/auth/login", json={"email": "demo@weird.studio", "password": "demo1234"})
        assert r.json()["user"]["is_pro"] is True


# ========== UPLOADS (library) ==========
class TestUploads:
    def test_upload_list_rename_assign_delete(self, s):
        # Ensure demo user is PRO (in case a previous test cancelled it)
        _restore_demo_pro()
        # Use demo PRO user so we can freely upload
        r = s.post(f"{API}/auth/login", json={"email": "demo@weird.studio", "password": "demo1234"})
        if r.status_code != 200:
            pytest.skip("demo user not seeded")
        token = r.json()["token"]
        h = _headers(token)

        files = {"file": ("clip.wav", _wav_bytes(), "audio/wav")}
        r = s.post(f"{API}/upload/audio", files=files, headers=h)
        assert r.status_code == 200
        j = r.json()
        fid = j["id"]

        # list — display_name and used_by present
        r = s.get(f"{API}/uploads", headers=h)
        assert r.status_code == 200
        found = next((d for d in r.json() if d["id"] == fid), None)
        assert found is not None
        assert found["display_name"] == "clip.wav"
        assert found["used_by"] == []

        # rename
        r = s.patch(f"{API}/uploads/{fid}", json={"display_name": "My Airhorn"}, headers=h)
        assert r.status_code == 200
        r = s.get(f"{API}/uploads", headers=h)
        found = next(d for d in r.json() if d["id"] == fid)
        assert found["display_name"] == "My Airhorn"

        # assign to a PRO-only tile (index 8) of first profile
        pid = s.get(f"{API}/profiles", headers=h).json()[0]["id"]
        url = f"/api/uploads/{fid}"
        r = s.patch(f"{API}/profiles/{pid}/tiles/8",
                    json={"sound_type": "file", "sound_url": url, "sound_name": "My Airhorn"}, headers=h)
        assert r.status_code == 200

        # used_by now populated + rename updates tile.sound_name
        r = s.patch(f"{API}/uploads/{fid}", json={"display_name": "Renamed Again"}, headers=h)
        assert r.status_code == 200
        r = s.get(f"{API}/uploads", headers=h)
        found = next(d for d in r.json() if d["id"] == fid)
        assert found["display_name"] == "Renamed Again"
        assert any(u["index"] == 8 for u in found["used_by"])
        prof = s.get(f"{API}/profiles/{pid}", headers=h).json()
        assert prof["tiles"][8]["sound_name"] == "Renamed Again"

        # delete clears tile
        r = s.delete(f"{API}/uploads/{fid}", headers=h)
        assert r.status_code == 200
        prof = s.get(f"{API}/profiles/{pid}", headers=h).json()
        assert prof["tiles"][8]["sound_type"] == "none"
        assert prof["tiles"][8]["sound_url"] == ""

    def test_upload_invalid_extension(self, s):
        u = _register_and_verify(s)
        files = {"file": ("bad.txt", b"hi", "text/plain")}
        r = s.post(f"{API}/upload/audio", files=files, headers=_headers(u["token"]))
        assert r.status_code == 400

    def test_free_upload_limit(self, s):
        u = _register_and_verify(s)
        for i in range(3):
            r = s.post(f"{API}/upload/audio",
                       files={"file": (f"x{i}.wav", _wav_bytes(), "audio/wav")},
                       headers=_headers(u["token"]))
            assert r.status_code == 200
        r = s.post(f"{API}/upload/audio",
                   files={"file": ("x4.wav", _wav_bytes(), "audio/wav")},
                   headers=_headers(u["token"]))
        assert r.status_code == 403

    def test_rename_unknown_404(self, s):
        u = _register_and_verify(s)
        r = s.patch(f"{API}/uploads/{'a' * 32}", json={"display_name": "x"}, headers=_headers(u["token"]))
        assert r.status_code == 404
