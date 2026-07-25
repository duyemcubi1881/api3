import os
import hmac as _hmac
import hashlib
import random
import string
import json
import time
import threading  # Thêm thư viện Lock cho cache thread-safe

from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, session, redirect
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

import firebase_admin
from firebase_admin import credentials, firestore

from dotenv import load_dotenv

load_dotenv()

# =========================================================
# App & Security Config
# =========================================================

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or "fallback_secret_key_DO_NOT_USE_IN_PRODUCTION"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=int(os.getenv("SESSION_MINUTES", "30")))
app.config["SESSION_COOKIE_SAMESITE"] = "None"
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
# Admin Auth
# =========================================================

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
if not ADMIN_PASSWORD_HASH:
    ADMIN_PASSWORD_HASH = generate_password_hash(os.getenv("ADMIN_PASSWORD", "admin123"))

# Optional HMAC request signature
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
# In-Memory Cache (Bộ nhớ đệm tránh spam Firestore)
# =========================================================
_cache_lock = threading.Lock()
KEY_CACHE = {}     # Cấu trúc: key_string -> {"timestamp": float, "data": dict, "exists": bool}
CACHE_TTL = 300    # Đợi 5 phút (300 giây) trước khi đọc lại Firestore cho cùng 1 key


def get_cached_key_doc(key_string: str) -> tuple:
    """
    Trả về (exists, key_data). Lấy từ bộ nhớ đệm nếu còn hạn để giảm tải Firestore.
    """
    now = time.time()
    with _cache_lock:
        cached = KEY_CACHE.get(key_string)
        if cached and (now - cached["timestamp"] < CACHE_TTL):
            return cached["exists"], cached["data"]

    # Cache miss -> Đọc trực tiếp từ database
    try:
        key_doc_ref = get_key_doc(key_string)
        doc = key_doc_ref.get()
        exists = doc.exists
        data = doc.to_dict() if exists else None
    except Exception as e:
        print(f"Error fetching from Firestore for cache: {e}")
        # Nếu DB lỗi tạm thời mà cache vẫn có dữ liệu cũ, trả về dữ liệu cũ để tránh sập hệ thống
        if cached:
            return cached["exists"], cached["data"]
        raise e

    # Lưu lại vào cache
    with _cache_lock:
        KEY_CACHE[key_string] = {
            "timestamp": now,
            "data": data,
            "exists": exists
        }
    return exists, data


def invalidate_key_cache(key_string: str):
    """Xóa cache của một key khi có cập nhật."""
    with _cache_lock:
        KEY_CACHE.pop(key_string, None)


def update_key_cache(key_string: str, exists: bool, data: dict):
    """Cập nhật dữ liệu mới trực tiếp vào cache để lần đọc sau có ngay thông tin mới."""
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
# Rate Limit Helper
# =========================================================

def _rate_limit_login(ip: str) -> bool:
    """Return True if the IP is rate-limited (10 attempts per 5 minutes)."""
    window = 300
    now = time.time()
    bucket = [t for t in _login_bucket.get(ip, []) if now - t < window]
    if len(bucket) >= LOGIN_RPM:
        _login_bucket[ip] = bucket
        return True
    bucket.append(now)
    _login_bucket[ip] = bucket
    return False


# =========================================================
# Duration Helpers
# =========================================================

def _parse_duration_from_request(data: dict) -> tuple:
    """
    Returns (duration_days, duration_hours, error_message).
    Priority: preset > hours > days. Default = 3 days.
    """
    preset = (data.get("duration_preset") or "").strip().lower()
    if preset in ("3h", "3hours", "3_gio", "3gio"):
        return 0, 3, None

    if "hours" in data and data.get("hours") is not None:
        try:
            hours = int(data["hours"])
        except (ValueError, TypeError):
            return None, None, "hours không hợp lệ — phải là số nguyên dương"
        if hours <= 0:
            return None, None, "Số giờ phải > 0"
        return 0, hours, None

    if "days" in data and data.get("days") is not None:
        try:
            days = int(data["days"])
        except (ValueError, TypeError):
            return None, None, "days không hợp lệ — phải là số nguyên dương"
        if days <= 0:
            return None, None, "Số ngày phải > 0"
        return days, None, None

    # Default: 3 days
    return 3, None, None


def _duration_label(key_data: dict) -> str:
    hours = key_data.get("duration_hours")
    if hours and int(hours) > 0:
        return f"{hours} giờ"
    days = key_data.get("duration_days", 0)
    return f"{days} ngày"


# =========================================================
# FIX: Múi giờ Việt Nam Đồng Nhất & Cực Kỳ Chính Xác
# =========================================================

VIETNAM_TZ = timezone(timedelta(hours=7))

def get_vietnam_time() -> datetime:
    # Trả về datetime timezone-naive đại diện cho giờ Việt Nam (UTC+7)
    return datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=7)

def _now_iso() -> str:
    return get_vietnam_time().isoformat()


def _parse_iso(dt_val):
    """
    Hàm parse thời gian cực kỳ mạnh mẽ để tránh lệch múi giờ.
    """
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
    """
    Tính thời điểm hết hạn dựa trên first_activated_at + duration.
    """
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


# =========================================================
# Firestore Helpers
# =========================================================

def _check_db() -> bool:
    return db is not None


def get_key_doc(key_string: str):
    if db is None:
        return None
    return db.collection("keys").document(key_string)


def _build_status(kd: dict, now: datetime) -> tuple:
    """Return (status_text, expires_display)."""
    if kd.get("is_banned"):
        return "BANNED", kd.get("expires_at") or "N/A"

    fa = kd.get("first_activated_at")
    if not fa:
        return "Chưa kích hoạt", "Chưa kích hoạt"

    exp = _compute_expiry(fa, kd)
    if exp is None:
        return "Chưa kích hoạt", "Chưa kích hoạt"

    expires_display = exp.strftime("%Y-%m-%d %H:%M:%S")
    status_text = "Hết Hạn" if now > exp else "Đang hoạt động"
    return status_text, expires_display


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

    # Chỉ ghi đè lên database khi:
    # 1. force_write = True (kích hoạt lần đầu hoặc phát hiện thiết bị vi phạm)
    # 2. Hoặc thiết bị này mới hoàn toàn
    # 3. Hoặc thời gian hoạt động cuối cùng của thiết bị này cách đây hơn 30 phút
    should_write = force_write or (not dev)
    if dev and not should_write:
        last_seen_str = dev.get("last_seen")
        if last_seen_str:
            last_seen_dt = _parse_iso(last_seen_str)
            if last_seen_dt:
                time_diff = now_dt - last_seen_dt
                if time_diff.total_seconds() > 1800:  # 30 minutes
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
        # Khi update thông tin thiết bị thành công, invalidate cache để thông tin đồng bộ
        invalidate_key_cache(key_doc_ref.id)
    except Exception as e:
        print("WARN update devices:", e)


# =========================================================
# Routes — Public
# =========================================================

@app.route("/")
def home():
    return jsonify({"status": "ok", "service": "Shop Boutique Key Backend"})


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "db": "connected" if db else "disconnected",
        "time": _now_iso(),
        "key_format": f"{KEY_PREFIX} - XXXXXXXX",
    })


@app.route("/api/session")
def session_info():
    return jsonify({"logged_in": bool(session.get("logged_in"))})


@app.route("/api/shorten")
def shorten_link():
    target_url = request.args.get("url")
    token_user = os.getenv("LAYMA_API_KEY") or "52f90acd7ef7e89e8c594189579ccb2b"
    if not target_url:
        return "Missing url parameter", 400
        
    import urllib.request
    import urllib.parse
    
    encoded_target_url = urllib.parse.quote(target_url)
    api_url = f"https://api.layma.net/api/admin/shortlink/quicklink?tokenUser={token_user}&format=json&url={encoded_target_url}"
    
    try:
        req = urllib.request.Request(
            api_url, 
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            res_body = response.read().decode('utf-8')
            data = json.loads(res_body)
            if data.get("success") and "html" in data:
                return redirect(data["html"])
    except Exception as e:
        print("Error format=json:", e)
        
    # Fallback to format=text
    try:
        api_url_text = f"https://api.layma.net/api/admin/shortlink/quicklink?tokenUser={token_user}&format=text&url={encoded_target_url}"
        req_text = urllib.request.Request(
            api_url_text, 
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req_text, timeout=10) as response_text:
            text_url = response_text.read().decode('utf-8').strip()
            if text_url.startswith("http"):
                return redirect(text_url)
    except Exception as e:
        print("Error format=text:", e)
        
    return redirect(target_url)


# =========================================================
# Routes — Auth
# =========================================================

@app.route("/api/login", methods=["POST"])
@require_json
def login():
    ip = request.headers.get("CF-Connecting-IP") or request.remote_addr or "0.0.0.0"
    if _rate_limit_login(ip):
        return jsonify({"error": "Vượt quá số lần thử. Thử lại sau 5 phút."}), 429

    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
        session.clear()
        session["logged_in"] = True
        session.permanent = True
        return jsonify({"message": "Đăng nhập thành công!"}), 200

    return jsonify({"error": "Tài khoản hoặc mật khẩu không đúng."}), 401


@app.route("/api/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return jsonify({"message": "Đăng xuất thành công."}), 200


# =========================================================
# Routes — Key Management (Admin)
# =========================================================

@app.route("/api/createkey", methods=["POST"])
@login_required
@require_json
def create_key():
    if not _check_db():
        return jsonify({"error": "Lỗi kết nối cơ sở dữ liệu"}), 500

    data = request.get_json() or {}
    duration_days, duration_hours, dur_err = _parse_duration_from_request(data)
    if dur_err:
        return jsonify({"error": dur_err}), 400

    key_type = data.get("key_type", "single_device")
    if key_type not in ("single_device", "multi_device"):
        return jsonify({"error": "key_type không hợp lệ"}), 400

    for _ in range(5):
        key_string = generate_key_string()
        key_doc_ref = get_key_doc(key_string)
        # Bypassing cache checking here for security, directly checking DB existence
        if not key_doc_ref.get().exists:
            break
    else:
        return jsonify({"error": "Không thể tạo key duy nhất — thử lại"}), 500

    key_data = {
        "key_string": key_string,
        "key_type": key_type,
        "duration_days": duration_days or 0,
        "duration_hours": duration_hours,
        "expires_at": None,
        "created_at": _now_iso(),
        "created_by": (data.get("created_by") or "AdminPanel").strip()[:64],
        "note": (data.get("note") or "").strip()[:256],
        "hwid": None,
        "ip_address": None,
        "first_activated_at": None,
        "is_banned": False,
        "violations": 0,
        "devices": {},
    }

    try:
        key_doc_ref.set(key_data)
        # Nạp thẳng thông tin key vừa tạo vào cache
        update_key_cache(key_string, True, key_data)
        
        resp = {
            "message": "Tạo key thành công!",
            "key": key_string,
            "key_type": key_type,
            "duration_label": _duration_label(key_data),
        }
        if duration_hours:
            resp["duration_hours"] = duration_hours
        else:
            resp["duration_days"] = duration_days
        return jsonify(resp), 201
    except Exception as e:
        return jsonify({"error": f"Lỗi tạo key: {e}"}), 500


@app.route("/api/createkey3h", methods=["POST"])
@login_required
@require_json
def create_key_3h():
    """Shortcut: tạo key 3 giờ single_device."""
    if not _check_db():
        return jsonify({"error": "Lỗi kết nối cơ sở dữ liệu"}), 500

    data = request.get_json() or {}
    key_type = data.get("key_type", "single_device")
    if key_type not in ("single_device", "multi_device"):
        return jsonify({"error": "key_type không hợp lệ"}), 400

    for _ in range(5):
        key_string = generate_key_string()
        key_doc_ref = get_key_doc(key_string)
        if not key_doc_ref.get().exists:
            break
    else:
        return jsonify({"error": "Không thể tạo key duy nhất — thử lại"}), 500

    key_data = {
        "key_string": key_string,
        "key_type": key_type,
        "duration_days": 0,
        "duration_hours": 3,
        "expires_at": None,
        "created_at": _now_iso(),
        "created_by": (data.get("created_by") or "AdminPanel").strip()[:64],
        "note": (data.get("note") or "Key 3 giờ").strip()[:256],
        "hwid": None,
        "ip_address": None,
        "first_activated_at": None,
        "is_banned": False,
        "violations": 0,
        "devices": {},
    }

    try:
        key_doc_ref.set(key_data)
        # Nạp thẳng thông tin key vừa tạo vào cache
        update_key_cache(key_string, True, key_data)
        
        return jsonify({
            "message": "Tạo key 3 giờ thành công!",
            "key": key_string,
            "key_type": key_type,
            "duration_hours": 3,
            "duration_label": "3 giờ",
        }), 201
    except Exception as e:
        return jsonify({"error": f"Lỗi tạo key: {e}"}), 500


@app.route("/api/deletekey", methods=["POST"])
@login_required
@require_json
def delete_key():
    if not _check_db():
        return jsonify({"error": "DB error"}), 500

    data = request.get_json() or {}
    key_string = (data.get("key") or "").strip()
    if not key_string:
        return jsonify({"error": "Thiếu key"}), 400

    ref = get_key_doc(key_string)
    doc = ref.get()
    if not doc.exists:
        return jsonify({"error": "Key không tồn tại"}), 404

    try:
        for log_doc in ref.collection("access_logs").limit(500).stream():
            log_doc.reference.delete()
    except Exception as e:
        print("WARN delete access_logs:", e)

    ref.delete()
    # Invalidate cache khi xóa key
    invalidate_key_cache(key_string)
    return jsonify({"message": f"Đã xoá {key_string}"}), 200


@app.route("/api/ban", methods=["POST"])
@login_required
@require_json
def ban_key():
    if not _check_db():
        return jsonify({"error": "DB error"}), 500

    data = request.get_json() or {}
    key_string = (data.get("key") or "").strip()
    if not key_string:
        return jsonify({"error": "Thiếu key"}), 400

    ref = get_key_doc(key_string)
    if not ref.get().exists:
        return jsonify({"error": "Key không tồn tại"}), 404

    ref.update({"is_banned": True})
    # Invalidate cache khi ban key
    invalidate_key_cache(key_string)
    return jsonify({"message": f"Đã ban {key_string}"}), 200


@app.route("/api/unban", methods=["POST"])
@login_required
@require_json
def unban_key():
    if not _check_db():
        return jsonify({"error": "DB error"}), 500

    data = request.get_json() or {}
    key_string = (data.get("key") or "").strip()
    if not key_string:
        return jsonify({"error": "Thiếu key"}), 400

    ref = get_key_doc(key_string)
    if not ref.get().exists:
        return jsonify({"error": "Key không tồn tại"}), 404

    ref.update({"is_banned": False})
    # Invalidate cache khi unban key
    invalidate_key_cache(key_string)
    return jsonify({"message": f"Đã unban {key_string}"}), 200


# =========================================================
# Routes — Key Info (Admin)
# =========================================================

@app.route("/api/keyinfo/<path:key_string>")
@login_required
def key_info(key_string: str):
    if not _check_db():
        return jsonify({"error": "DB error"}), 500

    key_doc_ref = get_key_doc(key_string)
    doc = key_doc_ref.get()
    if not doc.exists:
        return jsonify({"error": "Key không tồn tại"}), 404

    d = doc.to_dict()
    # Cập nhật cache với dữ liệu thực tế vừa đọc
    update_key_cache(key_string, True, d)

    now = get_vietnam_time()
    status_text, expires_display = _build_status(d, now)

    return jsonify({
        "key": d.get("key_string"),
        "key_type": d.get("key_type", "single_device"),
        "status": status_text,
        "is_banned": d.get("is_banned", False),
        "expires_at": expires_display,
        "duration_days": d.get("duration_days", 0),
        "duration_hours": d.get("duration_hours"),
        "duration_label": _duration_label(d),
        "hwid": d.get("hwid") or "Chưa đăng ký",
        "ip_address": d.get("ip_address") or "N/A",
        "first_activated_at": d.get("first_activated_at") or "Chưa kích hoạt",
        "created_by": d.get("created_by"),
        "created_at": d.get("created_at"),
        "note": d.get("note", ""),
        "violations": d.get("violations", 0),
        "devices": d.get("devices", {}),
    })


@app.route("/api/keystats/<path:key_string>")
@login_required
def key_stats(key_string: str):
    if not _check_db():
        return jsonify({"error": "DB error"}), 500

    key_doc_ref = get_key_doc(key_string)
    doc = key_doc_ref.get()
    if not doc.exists:
        return jsonify({"error": "Key không tồn tại"}), 404

    d = doc.to_dict()
    # Đồng bộ cache
    update_key_cache(key_string, True, d)
    
    devices: dict = d.get("devices") or {}
    total_devices = len(devices)
    limit = min(int(request.args.get("limit", 30)), 100)

    logs = []
    try:
        log_docs = (
            key_doc_ref.collection("access_logs")
            .order_by("ts", direction=firestore.Query.DESCENDING)
            .limit(limit)
            .stream()
        )
        logs = [ld.to_dict() for ld in log_docs]
    except Exception as e:
        print("WARN keystats logs:", e)

    last_used = logs[0].get("ts") if logs else None
    now = get_vietnam_time()
    active_devices = sum(
        1
        for dev in devices.values()
        if dev.get("last_seen")
        and _parse_iso(dev["last_seen"])
        and (now - _parse_iso(dev["last_seen"])) < timedelta(hours=24)
    )

    return jsonify({
        "key": key_string,
        "total_devices": total_devices,
        "active_devices": active_devices,
        "last_used": last_used,
        "violations": d.get("violations", 0),
        "duration_label": _duration_label(d),
        "logs": logs,
    })


@app.route("/api/keys")
@login_required
def get_all_keys():
    if not _check_db():
        return jsonify({"error": "DB error"}), 500

    try:
        page = max(1, int(request.args.get("page", "1")))
        page_size = min(max(1, int(request.args.get("page_size", "100"))), 500)
        start = (page - 1) * page_size

        keys_ref = db.collection("keys")
        
        # TỐI ƯU 1: Đếm tổng số lượng key dùng truy vấn Aggregation Count của Firestore (cực rẻ, tránh tốn phí load dữ liệu)
        try:
            total = keys_ref.count().get()[0].value
        except Exception as e:
            print("Failed to get count via count():", e)
            try:
                # Fallback: Chỉ select các trường ID trống (rất nhanh và rẻ)
                total = len(list(keys_ref.select([]).stream()))
            except Exception:
                total = 0

        # TỐI ƯU 2: Phân trang thực tế ngay trên Firestore, chỉ stream đúng số tài liệu cần hiển thị
        try:
            query = keys_ref.order_by("created_at", direction=firestore.Query.DESCENDING)
            docs = list(query.offset(start).limit(page_size).stream())
        except Exception as e:
            print("Failed to paginate with offset/limit:", e)
            # Tránh crash: fallback load bình thường nếu SDK không hỗ trợ offset/limit
            try:
                all_docs = list(keys_ref.order_by("created_at", direction=firestore.Query.DESCENDING).stream())
            except Exception:
                all_docs = list(keys_ref.stream())
            docs = all_docs[start : start + page_size]

        now = get_vietnam_time()
        rows = []
        for key_doc in docs:
            kd = key_doc.to_dict()
            status_text, expires_display = _build_status(kd, now)
            rows.append({
                "key_string": kd.get("key_string"),
                "key_type": kd.get("key_type", "single_device"),
                "expires_at": expires_display,
                "duration_label": _duration_label(kd),
                "duration_hours": kd.get("duration_hours"),
                "duration_days": kd.get("duration_days", 0),
                "hwid": kd.get("hwid") or "Chưa đăng ký",
                "ip_address": kd.get("ip_address") or "N/A",
                "first_activated_at": kd.get("first_activated_at") or "Chưa kích hoạt",
                "created_by": kd.get("created_by"),
                "created_at": kd.get("created_at"),
                "is_banned": bool(kd.get("is_banned")),
                "status_text": status_text,
                "violations": kd.get("violations", 0),
                "note": kd.get("note", ""),
            })

        return jsonify({"items": rows, "total": total, "page": page, "page_size": page_size})

    except Exception as e:
        return jsonify({"error": f"Lỗi khi tải keys: {str(e)}"}), 500


# =========================================================
# Routes — Redeem (Client)
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
    machine_name = (data.get("machine_name") or "UnknownMachine").strip()
    ip_address   = request.headers.get("CF-Connecting-IP") or request.remote_addr

    extra_info = {
        "windows_version": data.get("windows_version", "N/A"),
        "cpu_name":        data.get("cpu_name", "N/A"),
        "disk_serial":     data.get("disk_serial", "N/A"),
        "ram_total_gb":    data.get("ram_total_gb", "N/A"),
        "gpu_name":        data.get("gpu_name", "N/A"),
        "client_version":  data.get("client_version", "N/A"),
    }

    # ── Validate input ──────────────────────────────────────────────
    if not key_string or not hwid:
        return jsonify({"status": "error", "message": "Thiếu key hoặc HWID"}), 400

    if not is_valid_key_format(key_string):
        return jsonify({"status": "error", "message": "Định dạng key không hợp lệ"}), 400

    # ── Fetch key document (Đã tối ưu hóa qua RAM Cache) ────────────
    exists, key_data = get_cached_key_doc(key_string)

    if not exists:
        return jsonify({"status": "error", "message": "Key không tồn tại"}), 404

    # ── Banned check ────────────────────────────────────────────────
    if key_data.get("is_banned"):
        return jsonify({"status": "error", "message": "Key đã bị cấm"}), 403

    now = get_vietnam_time()
    first_activated_at = key_data.get("first_activated_at")
    key_type           = key_data.get("key_type", "single_device")
    key_doc_ref        = get_key_doc(key_string)

    # ── FIRST ACTIVATION ────────────────────────────────────────────
    if not first_activated_at:
        exp_dt = _compute_expiry(now.isoformat(), key_data)

        if exp_dt is None:
            return jsonify({
                "status": "error",
                "message": "Key không có thời hạn hợp lệ, liên hệ admin",
            }), 400

        expires_at = exp_dt.isoformat()
        updates = {
            "first_activated_at": now.isoformat(),
            "expires_at": expires_at,
            "hwid": hwid,
            "ip_address": ip_address,
        }
        
        try:
            key_doc_ref.update(updates)
            # Invalidate cache của key này ngay lập tức để đồng bộ lại thông tin mới kích hoạt
            invalidate_key_cache(key_string)
            key_data.update(updates)
        except Exception as e:
            return jsonify({"status": "error", "message": f"Lỗi kích hoạt key: {e}"}), 500

        update_usage_tracking(key_doc_ref, key_data, hwid, machine_name, ip_address, extra_info, force_write=True)

        # Tính số giây còn lại cho game client
        remaining_seconds = int((exp_dt - now).total_seconds())
        if remaining_seconds < 0: remaining_seconds = 0

        return jsonify({
            "status": "success",
            "message": "Key kích hoạt thành công!",
            "expires_at": expires_at,
            "expires_display": exp_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_label": _duration_label(key_data),
            "expiry_left": str(remaining_seconds)  # Trả về số giây còn lại cho game client
        }), 200

    # ── EXPIRY CHECK ─────────────────────────────────────────────────
    exp = _compute_expiry(first_activated_at, key_data)

    if exp is None:
        return jsonify({"status": "error", "message": "Key không có thời hạn hợp lệ"}), 400

    if now > exp:
        return jsonify({
            "status": "error",
            "message": "Key đã hết hạn",
            "expired_at": exp.strftime("%Y-%m-%d %H:%M:%S"),
        }), 403

    # ── HWID ENFORCEMENT (single_device) ────────────────────────────
    stored_hwid = key_data.get("hwid")
    if key_type == "single_device" and stored_hwid and stored_hwid != hwid:
        try:
            key_doc_ref.update({"violations": firestore.Increment(1)})
            invalidate_key_cache(key_string)
        except Exception:
            pass
        update_usage_tracking(key_doc_ref, key_data, hwid, machine_name, ip_address, extra_info, force_write=True)
        return jsonify({
            "status": "error",
            "message": "Key này đã được kích hoạt trên thiết bị khác",
            "registered_hwid": stored_hwid,
            "your_hwid": hwid,
        }), 403

    # ── SUCCESS ──────────────────────────────────────────────────────
    update_usage_tracking(key_doc_ref, key_data, hwid, machine_name, ip_address, extra_info, force_write=False)

    # Tính số giây còn lại
    remaining_seconds = int((exp - now).total_seconds())
    if remaining_seconds < 0: remaining_seconds = 0

    return jsonify({
        "status": "success",
        "message": "Key hợp lệ",
        "expires_at": exp.isoformat(),
        "expires_display": exp.strftime("%Y-%m-%d %H:%M:%S"),
        "registered_hwid": stored_hwid,
        "current_server_time": now.isoformat(),
        "duration_label": _duration_label(key_data),
        "expiry_left": str(remaining_seconds)  # Trả về số giây còn lại cho game client
    }), 200


# =========================================================
# Entry Point
# =========================================================

if __name__ == "__main__":
    app.run(debug=True, port=5000)
