import os
import hmac as _hmac
import hashlib
import random
import string
import json
import time
import base64
import threading

from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, session, redirect
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

import firebase_admin
from firebase_admin import credentials, firestore

from dotenv import load_dotenv

# Import cryptography để ký số RSA/Ed25519
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

load_dotenv()

# =========================================================
# App & Security Config
# =========================================================

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or "fallback_secret_key_DO_NOT_USE_IN_PRODUCTION"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=int(os.getenv("SESSION_MINUTES", "30")))
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True

ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",")]
CORS(
    app,
    supports_credentials=True,
    origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS != ["*"] else "*",
)

# Anti-bruteforce (in-memory)
LOGIN_RPM = int(os.getenv("LOGIN_RPM", "10"))
_login_bucket: dict = {}

# =========================================================
# RSA Private Key Setup (Dùng ký response chống Fake Server)
# =========================================================

SERVER_PRIVATE_KEY_PEM = os.getenv("RSA_PRIVATE_KEY")

# Tự động sinh RSA Key nếu chưa cấu hình trong .env (Dùng cho dev)
if not SERVER_PRIVATE_KEY_PEM:
    from cryptography.hazmat.primitives.asymmetric import rsa
    _key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    _priv_bytes = _key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    _pub_bytes = _key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    SERVER_PRIVATE_KEY = _key
    print("⚠️ WARN: Dùng RSA Key tự sinh ngẫu nhiên. Vui lòng cấu hình RSA_PRIVATE_KEY trong file .env!")
    print("🔑 PUBLIC KEY CỦA CLIENT (Nhúng vào C++/Client app):\n" + _pub_bytes.decode())
else:
    SERVER_PRIVATE_KEY = serialization.load_pem_private_key(
        SERVER_PRIVATE_KEY_PEM.encode(),
        password=None,
        backend=default_backend()
    )

def sign_payload(payload_str: str) -> str:
    """Ký số chuỗi payload bằng RSA Private Key và trả về Base64 signature."""
    signature = SERVER_PRIVATE_KEY.sign(
        payload_str.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

# =========================================================
# Firebase Init
# =========================================================

db = None

try:
    firebase_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_KEY")
    cred = None

    if firebase_json:
        cfg = json.loads(firebase_json)
        if "private_key" in cfg:
            cfg["private_key"] = cfg["private_key"].replace("\\n", "\n")
        cred = credentials.Certificate(cfg)
    else:
        firebase_config = {
            "type": os.getenv("FIREBASE_TYPE"),
            "project_id": os.getenv("FIREBASE_PROJECT_ID"),
            "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
            "private_key": (os.getenv("FIREBASE_PRIVATE_KEY") or "").replace("\\n", "\n") or None,
            "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
            "client_id": os.getenv("FIREBASE_CLIENT_ID"),
            "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
            "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
            "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL"),
            "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL"),
            "universe_domain": os.getenv("FIREBASE_UNIVERSE_DOMAIN"),
        }
        if all(v for v in firebase_config.values()):
            cred = credentials.Certificate(firebase_config)

    if cred:
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("✅ Firebase connected")
    else:
        print("❌ Firebase not initialized — check environment variables")

except Exception as e:
    print("🔥 Firebase init error:", e)

# =========================================================
# Admin Auth & Client HMAC
# =========================================================

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
if not ADMIN_PASSWORD_HASH:
    ADMIN_PASSWORD_HASH = generate_password_hash(os.getenv("ADMIN_PASSWORD", "admin123"))

CLIENT_HMAC_SECRET = os.getenv("CLIENT_HMAC_SECRET")

# =========================================================
# Key Format: ShopBoutique - XXXXXXXX
# =========================================================

KEY_PREFIX = "ImguiFree"
KEY_SUFFIX_LENGTH = 8
KEY_CHARS = string.ascii_uppercase + string.digits


def generate_key_string() -> str:
    suffix = "".join(random.choices(KEY_CHARS, k=KEY_SUFFIX_LENGTH))
    return f"{KEY_PREFIX} - {suffix}"


def is_valid_key_format(key_string: str) -> bool:
    if not isinstance(key_string, str):
        return False
    expected_sep = f"{KEY_PREFIX} - "
    if not key_string.startswith(expected_sep):
        return False
    suffix = key_string[len(expected_sep):]
    if len(suffix) < 3 or len(suffix) > 32:
        return False
    return suffix.isalnum()

# =========================================================
# In-Memory Cache
# =========================================================
_cache_lock = threading.Lock()
KEY_CACHE = {}
CACHE_TTL = 300


def get_cached_key_doc(key_string: str) -> tuple:
    now = time.time()
    with _cache_lock:
        cached = KEY_CACHE.get(key_string)
        if cached and (now - cached["timestamp"] < CACHE_TTL):
            return cached["exists"], cached["data"]

    try:
        key_doc_ref = get_key_doc(key_string)
        doc = key_doc_ref.get()
        exists = doc.exists
        data = doc.to_dict() if exists else None
    except Exception as e:
        print(f"Error fetching from Firestore for cache: {e}")
        if cached:
            return cached["exists"], cached["data"]
        raise e

    with _cache_lock:
        KEY_CACHE[key_string] = {
            "timestamp": now,
            "data": data,
            "exists": exists
        }
    return exists, data


def invalidate_key_cache(key_string: str):
    with _cache_lock:
        KEY_CACHE.pop(key_string, None)


def update_key_cache(key_string: str, exists: bool, data: dict):
    now = time.time()
    with _cache_lock:
        KEY_CACHE[key_string] = {
            "timestamp": now,
            "data": data,
            "exists": exists
        }

# =========================================================
# Decorators
# =========================================================

def require_json(f):
    @wraps(f)
    def w(*a, **k):
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 415
        return f(*a, **k)
    return w


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Không được ủy quyền. Vui lòng đăng nhập."}), 401
        return f(*args, **kwargs)
    return decorated


def hmac_required(f):
    @wraps(f)
    def w(*a, **k):
        if not CLIENT_HMAC_SECRET:
            return f(*a, **k)
        sig = request.headers.get("X-Client-Sign")
        ts = request.headers.get("X-Client-Ts")
        if not sig or not ts:
            return jsonify({"status": "error", "message": "Missing signature"}), 401
        try:
            payload = request.get_data() + ts.encode()
            calc = _hmac.new(CLIENT_HMAC_SECRET.encode(), payload, hashlib.sha256).hexdigest()
            if not _hmac.compare_digest(calc, sig):
                return jsonify({"status": "error", "message": "Invalid signature"}), 401
            if abs(int(time.time()) - int(ts)) > 60:
                return jsonify({"status": "error", "message": "Expired signature"}), 401
        except Exception:
            return jsonify({"status": "error", "message": "Signature error"}), 401
        return f(*a, **k)
    return w

# =========================================================
# Helpers
# =========================================================

def _rate_limit_login(ip: str) -> bool:
    window = 300
    now = time.time()
    bucket = [t for t in _login_bucket.get(ip, []) if now - t < window]
    if len(bucket) >= LOGIN_RPM:
        _login_bucket[ip] = bucket
        return True
    bucket.append(now)
    _login_bucket[ip] = bucket
    return False


VIETNAM_TZ = timezone(timedelta(hours=7))

def get_vietnam_time() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=7)

def _now_iso() -> str:
    return get_vietnam_time().isoformat()


def _parse_iso(dt_val):
    if dt_val is None:
        return None
    dt = None
    if isinstance(dt_val, datetime):
        dt = dt_val
    elif isinstance(dt_val, str):
        try:
            cleaned_str = dt_val
            if cleaned_str.endswith('Z'):
                cleaned_str = cleaned_str[:-1] + '+00:00'
            dt = datetime.fromisoformat(cleaned_str)
        except Exception:
            return None
    else:
        try:
            dt = dt_val.to_datetime()
        except Exception:
            return None

    if dt is None:
        return None

    if dt.tzinfo is not None:
        return dt.astimezone(VIETNAM_TZ).replace(tzinfo=None)
    
    return dt


def _compute_expiry(first_activated_at: str, key_data: dict):
    dt = _parse_iso(first_activated_at)
    if dt is None:
        return None

    hours = key_data.get("duration_hours")
    if hours is not None:
        try:
            hours = int(hours)
        except (ValueError, TypeError):
            hours = 0
        if hours > 0:
            return dt + timedelta(hours=hours)

    days = key_data.get("duration_days", 0)
    try:
        days = int(days)
    except (ValueError, TypeError):
        days = 0

    if days <= 0:
        return None

    return dt + timedelta(days=days)


def _parse_duration_from_request(data: dict) -> tuple:
    preset = (data.get("duration_preset") or "").strip().lower()
    if preset in ("3h", "3hours", "3_gio", "3gio"):
        return 0, 3, None

    if "hours" in data and data.get("hours") is not None:
        try:
            hours = int(data["hours"])
        except (ValueError, TypeError):
            return None, None, "hours không hợp lệ"
        if hours <= 0:
            return None, None, "Số giờ phải > 0"
        return 0, hours, None

    if "days" in data and data.get("days") is not None:
        try:
            days = int(data["days"])
        except (ValueError, TypeError):
            return None, None, "days không hợp lệ"
        if days <= 0:
            return None, None, "Số ngày phải > 0"
        return days, None, None

    return 3, None, None


def _duration_label(key_data: dict) -> str:
    hours = key_data.get("duration_hours")
    if hours and int(hours) > 0:
        return f"{hours} giờ"
    days = key_data.get("duration_days", 0)
    return f"{days} ngày"

# =========================================================
# Firestore Helpers
# =========================================================

def _check_db() -> bool:
    return db is not None


def get_key_doc(key_string: str):
    if db is None:
        return None
    return db.collection("keys").document(key_string)


def update_usage_tracking(
    key_doc_ref,
    key_data: dict,
    hwid: str,
    machine_name: str,
    ip_address: str,
    extra_info: dict = None,
    force_write: bool = False,
):
    extra_info = extra_info or {}
    machine_name = machine_name or "UnknownMachine"
    now_iso = _now_iso()
    now_dt = get_vietnam_time()

    devices = key_data.get("devices") or {}
    dev = devices.get(hwid)

    should_write = force_write or (not dev)
    if dev and not should_write:
        last_seen_str = dev.get("last_seen")
        if last_seen_str:
            last_seen_dt = _parse_iso(last_seen_str)
            if last_seen_dt:
                if (now_dt - last_seen_dt).total_seconds() > 1800:
                    should_write = True
            else:
                should_write = True
        else:
            should_write = True

    if not should_write:
        return

    log_entry = {
        "ts": now_iso,
        "hwid": hwid,
        "machine_name": machine_name,
        "ip": ip_address,
        "action": "redeem",
        **extra_info,
    }

    try:
        key_doc_ref.collection("access_logs").add(log_entry)
    except Exception as e:
        print("WARN access_logs:", e)

    new_entry = {
        "hwid": hwid,
        "machine_name": machine_name,
        "first_seen": now_iso if not dev else dev.get("first_seen", now_iso),
        "last_seen": now_iso,
        "last_ip": ip_address,
        "usage_count": (dev.get("usage_count", 0) + 1) if dev else 1,
        "extra_info": extra_info,
    }

    try:
        key_doc_ref.update({f"devices.{hwid}": new_entry})
        invalidate_key_cache(key_doc_ref.id)
    except Exception as e:
        print("WARN update devices:", e)

# =========================================================
# Routes — Redeem (Nâng cấp bảo mật ký số RSA & Nonce)
# =========================================================

@app.route("/api/redeem", methods=["POST"])
@require_json
@hmac_required
def redeem_key():
    if not _check_db():
        return jsonify({"status": "error", "message": "Lỗi cơ sở dữ liệu"}), 500

    data = request.get_json() or {}
    key_string   = (data.get("key") or "").strip()
    hwid         = (data.get("hwid") or "").strip()
    nonce        = (data.get("nonce") or "").strip()  # Chuỗi chống replay
    machine_name = (data.get("machine_name") or "UnknownMachine").strip()
    ip_address   = request.headers.get("CF-Connecting-IP") or request.remote_addr

    if not key_string or not hwid:
        return jsonify({"status": "error", "message": "Thiếu key hoặc HWID"}), 400

    if not is_valid_key_format(key_string):
        return jsonify({"status": "error", "message": "Định dạng key không hợp lệ"}), 400

    # ── Fetch key (RAM Cache) ───────────────────────────────────────
    exists, key_data = get_cached_key_doc(key_string)

    if not exists:
        return jsonify({"status": "error", "message": "Key không tồn tại"}), 404

    if key_data.get("is_banned"):
        return jsonify({"status": "error", "message": "Key đã bị cấm"}), 403

    now = get_vietnam_time()
    first_activated_at = key_data.get("first_activated_at")
    key_type           = key_data.get("key_type", "single_device")
    key_doc_ref        = get_key_doc(key_string)

    # ── KÍCH HOẠT LẦN ĐẦU ──────────────────────────────────────────
    if not first_activated_at:
        exp_dt = _compute_expiry(now.isoformat(), key_data)
        if exp_dt is None:
            return jsonify({"status": "error", "message": "Key không có thời hạn hợp lệ"}), 400

        expires_at = exp_dt.isoformat()
        updates = {
            "first_activated_at": now.isoformat(),
            "expires_at": expires_at,
            "hwid": hwid,
            "ip_address": ip_address,
        }
        
        try:
            key_doc_ref.update(updates)
            invalidate_key_cache(key_string)
            key_data.update(updates)
        except Exception as e:
            return jsonify({"status": "error", "message": f"Lỗi kích hoạt key: {e}"}), 500

        update_usage_tracking(key_doc_ref, key_data, hwid, machine_name, ip_address, force_write=True)

        remaining_seconds = max(0, int((exp_dt - now).total_seconds()))

        # 🔐 TẠO CHỮ KÝ BẢO MẬT (Chống Fake Server)
        server_ts = int(time.time())
        # Tạo chuỗi dữ liệu gốc bắt buộc chứa: HWID + KEY + EXPIRY + NONCE + TIMESTAMP
        raw_payload = f"{hwid}|{key_string}|{remaining_seconds}|{nonce}|{server_ts}"
        signature = sign_payload(raw_payload)

        return jsonify({
            "status": "success",
            "message": "Key kích hoạt thành công!",
            "expires_at": expires_at,
            "expires_display": exp_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_label": _duration_label(key_data),
            "expiry_left": str(remaining_seconds),
            "server_ts": server_ts,
            "nonce": nonce,
            "signature": signature  # Client dùng Public Key để verify signature này!
        }), 200

    # ── KIỂM TRA HẠN SỬ DỤNG ─────────────────────────────────────────
    exp = _compute_expiry(first_activated_at, key_data)
    if exp is None or now > exp:
        return jsonify({"status": "error", "message": "Key đã hết hạn"}), 403

    # ── HWID CHECK (single_device) ──────────────────────────────────
    stored_hwid = key_data.get("hwid")
    if key_type == "single_device" and stored_hwid and stored_hwid != hwid:
        try:
            key_doc_ref.update({"violations": firestore.Increment(1)})
            invalidate_key_cache(key_string)
        except Exception:
            pass
        update_usage_tracking(key_doc_ref, key_data, hwid, machine_name, ip_address, force_write=True)
        return jsonify({
            "status": "error",
            "message": "Key này đã được kích hoạt trên thiết bị khác",
        }), 403

    # ── THÀNH CÔNG (TRẢ VỀ RESPONSE KÝ SỐ) ───────────────────────────
    update_usage_tracking(key_doc_ref, key_data, hwid, machine_name, ip_address, force_write=False)
    remaining_seconds = max(0, int((exp - now).total_seconds()))

    # 🔐 TẠO CHỮ KÝ BẢO MẬT (Chống Fake Server)
    server_ts = int(time.time())
    raw_payload = f"{hwid}|{key_string}|{remaining_seconds}|{nonce}|{server_ts}"
    signature = sign_payload(raw_payload)

    return jsonify({
        "status": "success",
        "message": "Key hợp lệ",
        "expires_at": exp.isoformat(),
        "expires_display": exp.strftime("%Y-%m-%d %H:%M:%S"),
        "registered_hwid": stored_hwid,
        "duration_label": _duration_label(key_data),
        "expiry_left": str(remaining_seconds),
        "server_ts": server_ts,
        "nonce": nonce,
        "signature": signature  # Client dùng Public Key để verify signature này!
    }), 200

# Các API Admin giữ nguyên...
# [Các route /api/login, /api/createkey, /api/keys, ...] giữ nguyên như mã cũ

if __name__ == "__main__":
    app.run(debug=False, port=5000)
