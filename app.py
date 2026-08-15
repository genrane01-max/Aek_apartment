# ============================================================
# DORM BILLING — ระบบบิลหอพักอัตโนมัติ (Multi-Tenant SaaS)
# Flask + Firebase/Firestore + SlipOK + Render
# FINAL v8: Security Pack ครบ (Rate Limit+Redis, Constant-time compare,
#           Webhook signature enforced, Secret masking, Safer SlipOK calls)
# ============================================================
import os
import secrets
import io
import base64
import csv
import hmac
import hashlib
from datetime import date, timedelta, datetime

import requests
import qrcode
from PIL import Image
from flask import (Flask, render_template, request, jsonify, session,
                   send_file, redirect, Response)
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from google.cloud.firestore import Increment
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)

# ---- SECRET KEY ----
if os.environ.get("FLASK_SECRET_KEY"):
    app.secret_key = os.environ["FLASK_SECRET_KEY"]
else:
    app.secret_key = secrets.token_hex(32)

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=1)

# ---- Session Cookie ----
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true",
)

# ---- Rate Limiter ----
# 🔒 FIX: storage_uri now configurable. On Render with multiple
# workers/instances, in-memory storage counts requests separately per
# process, so the "5 per minute" limits below can effectively be bypassed.
# Set RATELIMIT_STORAGE_URI (e.g. redis://<host>:<port>) in Render env vars
# to make limits shared across all instances. If unset, behaves exactly as
# before (in-memory, per-process) so this change alone doesn't break anything.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

# ---- ค่าบริการ (Env จาก Render) ----
SUPERADMIN_PASSWORD = os.environ.get("SUPERADMIN_PASSWORD", "")
SYSTEM_FEE = 399                # ค่าเช่าระบบ / เดือน
ADDON_FEE = 199                 # ค่าเปิดตรวจสลิปอัตโนมัติ / เดือน
ADDON_CREDITS = 250             # จำนวนครั้งตรวจต่อเดือน
TRIAL_DAYS = 30                 # ทดลองฟรี (วัน)
SLIP_MAX_AGE_MIN = 15           # สลิปต้องไม่เก่ากว่านี้
PLATFORM_PROMPTPAY = os.environ.get("PLATFORM_PROMPTPAY", "")
PLATFORM_SLIPOK_KEY = os.environ.get("SLIPOK_API_KEY", "")
PLATFORM_SLIPOK_BRANCH = os.environ.get("SLIPOK_BRANCH_ID", "")

# ---- Firebase Firestore ----
if not firebase_admin._apps:
    fb_config = {
        "type": "service_account",
        "project_id": os.environ.get("FIREBASE_PROJECT_ID"),
        "private_key_id": os.environ.get("FIREBASE_PRIVATE_KEY_ID"),
        "private_key": os.environ.get("FIREBASE_PRIVATE_KEY", "").replace("\\n", "\n"),
        "client_email": os.environ.get("FIREBASE_CLIENT_EMAIL"),
        "client_id": os.environ.get("FIREBASE_CLIENT_ID"),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": os.environ.get("FIREBASE_CLIENT_CERT_URL"),
    }
    try:
        cred = credentials.Certificate(fb_config)
        firebase_admin.initialize_app(cred)
    except Exception as e:
        print(f"❌ Firebase Config Error: {e}")

db = firestore.client()

# ============================================================
# ตัวช่วย (Helpers)
# ============================================================
def dorm_ref(dorm_id):
    return db.collection("dorms").document(dorm_id)

def is_dorm_expired(dorm):
    exp = str(dorm.get("expiry_date") or "")
    return bool(exp and exp < date.today().isoformat())

def mask_key(key):
    return ("****" + key[-4:]) if key else ""

def get_current_dorm(allow_expired=False):
    dorm_id = session.get("dorm_id")
    if not dorm_id:
        return None, None
    doc = dorm_ref(dorm_id).get()
    if not doc.exists:
        session.pop("dorm_id", None)
        return None, None
    dorm = doc.to_dict()
    if not dorm.get("is_active", True):
        return None, None
    if is_dorm_expired(dorm) and not allow_expired:
        return None, None
    return dorm_id, dorm

def find_invoice_by_token(token):
    for dorm_doc in db.collection("dorms").stream():
        docs = list(dorm_ref(dorm_doc.id).collection("invoices")
                    .where("bill_token", "==", token).limit(1).stream())
        if docs:
            return {"dorm_id": dorm_doc.id, "id": docs[0].id, "data": docs[0].to_dict()}
    return None

def generate_qr_datauri(data):
    try:
        qr = qrcode.QRCode(box_size=10, border=2)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return ""

def compress_slip(file):
    img = Image.open(file).convert("RGB")
    max_dim = 900
    if max(img.size) > max_dim:
        ratio = max_dim / max(img.size)
        img = img.resize((int(img.width * ratio), int(img.height * ratio)), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=70)
    return base64.b64encode(buf.getvalue()).decode()

def _fmt_amount(a):
    a = round(float(a), 2)
    return str(int(a)) if a == int(a) else f"{a:.2f}".rstrip("0").rstrip(".")

def parse_extra_fees(raw):
    """รับรายการค่าใช้จ่ายอื่น [{'label':..., 'amount':...}] -> list ที่ผ่านการตรวจแล้ว"""
    result = []
    for item in (raw or []):
        if not isinstance(item, dict):
            continue
        label = (item.get("label") or "").strip()
        try:
            amount = float(item.get("amount") or 0)
        except (TypeError, ValueError):
            amount = 0
        if label and amount > 0:
            result.append({"label": label, "amount": round(amount, 2)})
    return result

def sanitize_csv(val):
    """กัน CSV Injection: เติม ' นำหน้าเครื่องหมายอันตราย (= + - @)"""
    val = str(val)
    if val and val[0] in ('=', '+', '-', '@'):
        return "'" + val
    return val

def slip_is_fresh(trans_date, trans_time, max_minutes=SLIP_MAX_AGE_MIN):
    """ปิดช่องโหว่: สลิปต้องเป็นของไม่เกิน X นาที"""
    if not trans_date or not trans_time:
        return True
    try:
        slip_dt = datetime.strptime(f"{trans_date} {trans_time}", "%Y%m%d %H:%M:%S")
        now_thai = datetime.utcnow() + timedelta(hours=7)
        diff = now_thai - slip_dt
        return timedelta(minutes=-5) <= diff <= timedelta(minutes=max_minutes)
    except ValueError:
        return True

def verify_platform_slip(file, expected_amount):
    """ตรวจสลิปผ่านสาขาแพลตฟอร์ม (ตัดเครดิตจากแพ็กเกจเรา)"""
    url = f"https://api.slipok.com/api/line/apikey/{PLATFORM_SLIPOK_BRANCH}"
    headers = {"x-authorization": PLATFORM_SLIPOK_KEY}
    files = {"files": (file.filename or "slip.jpg", file.stream, file.mimetype or "image/jpeg")}
    # 🔒 FIX: wrap the network call + JSON parse in try/except so a SlipOK
    # timeout / bad response returns a clean JSON error instead of a raw 500.
    try:
        resp = requests.post(url, headers=headers, files=files, data={"log": True}, timeout=15)
        res = resp.json()
    except Exception:
        return {"success": False, "message": "ตรวจสลิปผิดพลาด กรุณาลองใหม่"}
    print(f"--- PLATFORM SLIPOK: {res} ---")
    if not res.get("success"):
        return {"success": False, "message": res.get("message", "สลิปไม่ถูกต้อง")}
    d = res.get("data", {})
    trans_ref, amount = d.get("transRef"), float(d.get("amount", 0))
    if not trans_ref or amount <= 0:
        return {"success": False, "message": "ข้อมูลสลิปไม่สมบูรณ์"}
    if abs(amount - expected_amount) > 0.01:
        return {"success": False, "message": f"ยอดไม่ตรง (ต้อง {expected_amount:.0f} บาท / โอน {amount:.2f} บาท)"}
    if not slip_is_fresh(d.get("transDate"), d.get("transTime")):
        return {"success": False, "message": "สลิปเก่าเกินไป (ต้องโอนภายใน 15 นาทีที่ผ่านมา)"}
    return {"success": True, "trans_ref": trans_ref, "amount": amount, "data": d}

def mark_slip_used(trans_ref, amount, note=""):
    ref = db.collection("used_slips").document(trans_ref)
    if ref.get().exists:
        return False
    ref.set({"trans_ref": trans_ref, "amount": amount, "note": note,
             "used_at": firestore.SERVER_TIMESTAMP})
    return True

# ============================================================
# Transactions (กันโกง / กันสลิปซ้ำ)
# ============================================================
@firestore.transactional
def execute_mark_paid_transaction(transaction, invoice_ref, slip_ref, trans_ref, amount):
    if slip_ref.get(transaction=transaction).exists:
        return {"success": False, "message": "สลิปนี้เคยถูกใช้งานแล้ว"}
    cur = invoice_ref.get(transaction=transaction)
    if not cur.exists or cur.to_dict().get("status") == "paid":
        return {"success": False, "message": "บิลนี้ชำระแล้ว"}
    transaction.set(slip_ref, {"trans_ref": trans_ref, "amount": amount,
                               "used_at": firestore.SERVER_TIMESTAMP})
    transaction.update(invoice_ref, {"status": "paid", "trans_ref": trans_ref,
                                     "paid_at": firestore.SERVER_TIMESTAMP})
    return {"success": True}

@firestore.transactional
def execute_mark_waiting_transaction(transaction, invoice_ref, slip_b64, slip_filename):
    cur = invoice_ref.get(transaction=transaction)
    if not cur.exists or cur.to_dict().get("status") != "pending":
        return {"success": False, "message": "บิลนี้ไม่สามารถส่งสลิปได้อีก"}
    transaction.update(invoice_ref, {"status": "waiting_confirm", "slip_image": slip_b64,
                                     "slip_filename": slip_filename})
    return {"success": True}

@firestore.transactional
def execute_approve_invoice_transaction(transaction, invoice_ref):
    cur = invoice_ref.get(transaction=transaction)
    if not cur.exists:
        return {"success": False, "message": "ไม่พบบิล"}
    if cur.to_dict().get("status") != "waiting_confirm":
        return {"success": False, "message": "บิลนี้ไม่ได้รอการตรวจสอบ"}
    transaction.update(invoice_ref, {"status": "paid", "paid_at": firestore.SERVER_TIMESTAMP,
                                     "slip_image": "", "slip_filename": ""})
    return {"success": True}

@firestore.transactional
def execute_reject_invoice_transaction(transaction, invoice_ref):
    cur = invoice_ref.get(transaction=transaction)
    if not cur.exists:
        return {"success": False, "message": "ไม่พบบิล"}
    if cur.to_dict().get("status") != "waiting_confirm":
        return {"success": False, "message": "บิลนี้ไม่ได้รอการตรวจสอบ"}
    transaction.update(invoice_ref, {"status": "pending", "slip_image": "", "slip_filename": ""})
    return {"success": True}

# ============================================================
# หน้าเว็บหลัก
# ============================================================
@app.route("/")
def index():
    return redirect("/dorm/login")

@app.route("/manual")
def manual_page():
    return render_template("manual.html")

@app.route("/icon.png")
def app_icon():
    from PIL import Image, ImageDraw
    size = 180
    img = Image.new("RGBA", (size, size), (11, 15, 13, 255))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([5, 5, size-5, size-5], radius=38, outline=(212, 175, 55, 255), width=7)
    gold = (212, 175, 55, 255)
    d.polygon([(90, 40), (142, 70), (38, 70)], fill=gold)
    d.rectangle([45, 70, 135, 142], fill=gold)
    for x in range(58, 130, 19):
        for y in range(84, 128, 19):
            d.rectangle([x, y, x+10, y+10], fill=(11, 15, 13, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

@app.route("/manifest.json")
def manifest():
    return jsonify({
        "name": "ระบบบิลหอพักอัตโนมัติ",
        "short_name": "บิลหอพัก",
        "start_url": "/dorm/login",
        "display": "standalone",
        "background_color": "#0b0f0d",
        "theme_color": "#0b0f0d",
        "icons": [{"src": "/icon.png", "sizes": "180x180", "type": "image/png"}]
    })

# ============================================================
# SUPER ADMIN
# ============================================================
@app.route("/superadmin/login")
def superadmin_login_page():
    return render_template("superadmin_login.html")

@app.route("/superadmin")
def superadmin_page():
    if not session.get("is_superadmin"):
        return redirect("/superadmin/login")
    return render_template("superadmin.html")

@app.route("/api/superadmin/login", methods=["POST"])
@limiter.limit("5 per minute")
def superadmin_login():
    session.clear()  # 🔒 ล้าง session เก่า กัน session fixation
    data = request.get_json(silent=True) or {}
    if not SUPERADMIN_PASSWORD:
        return jsonify({"success": False, "message": "ยังไม่ได้ตั้งค่ารหัสผ่าน Super Admin ใน Render Secrets"}), 500
    # 🔒 FIX: constant-time comparison instead of ==
    if hmac.compare_digest(str(data.get("password") or ""), SUPERADMIN_PASSWORD):
        session["is_superadmin"] = True
        session.permanent = True
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "รหัสผ่านไม่ถูกต้อง"}), 401

@app.route("/api/superadmin/logout", methods=["POST"])
def superadmin_logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/superadmin/dorms", methods=["GET"])
def superadmin_list_dorms():
    if not session.get("is_superadmin"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    dorms = []
    for doc in db.collection("dorms").stream():
        d = doc.to_dict()
        d.pop("password_hash", None)
        d["slipok_api_key"] = mask_key(d.get("slipok_api_key"))
        d["id"] = doc.id
        waiting, paid_total = 0, 0.0
        for inv in dorm_ref(doc.id).collection("invoices").stream():
            st = inv.to_dict().get("status")
            if st == "waiting_confirm":
                waiting += 1
            if st == "paid":
                paid_total += float(inv.to_dict().get("total_amount", 0))
        d["waiting_count"] = waiting
        d["paid_total"] = round(paid_total, 2)
        dorms.append(d)
    return jsonify({"success": True, "dorms": dorms})

@app.route("/api/superadmin/dorms/<dorm_id>/branch", methods=["POST"])
def superadmin_set_branch(dorm_id):
    if not session.get("is_superadmin"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    branch_id = (data.get("slipok_branch_id") or "").strip()
    api_key = (data.get("slipok_api_key") or "").strip()
    if not branch_id or not api_key:
        return jsonify({"success": False, "message": "ต้องกรอกทั้ง Branch ID และ API Key"}), 400
    dorm_ref(dorm_id).update({
        "slipok_branch_id": branch_id,
        "slipok_api_key": api_key,
    })
    return jsonify({"success": True, "message": "ตั้งสาขา + API Key เรียบร้อย"})

@app.route("/api/superadmin/dorms/<dorm_id>/package", methods=["POST"])
def superadmin_set_package(dorm_id):
    if not session.get("is_superadmin"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    expiry = (data.get("expiry_date") or "").strip()
    if not expiry:
        return jsonify({"success": False, "message": "กรอกวันหมดอายุ"}), 400
    dorm_ref(dorm_id).update({"expiry_date": expiry})
    return jsonify({"success": True, "message": "อัปเดตวันหมดอายุเรียบร้อย"})

@app.route("/api/superadmin/dorms/<dorm_id>/toggle", methods=["POST"])
def superadmin_toggle_dorm(dorm_id):
    if not session.get("is_superadmin"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    doc = dorm_ref(dorm_id).get()
    if not doc.exists:
        return jsonify({"success": False, "message": "ไม่พบหอ"}), 404
    new_state = not doc.to_dict().get("is_active", True)
    dorm_ref(dorm_id).update({"is_active": new_state})
    return jsonify({"success": True, "is_active": new_state,
                    "message": "เปิดใช้งาน" if new_state else "ระงับการใช้งานแล้ว"})

@app.route("/api/superadmin/dorms/<dorm_id>/reset_password", methods=["POST"])
def superadmin_reset_password(dorm_id):
    if not session.get("is_superadmin"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    pwd = data.get("password") or ""
    if len(pwd) < 4:
        return jsonify({"success": False, "message": "รหัสต้องยาวอย่างน้อย 4 ตัว"}), 400
    dorm_ref(dorm_id).update({"password_hash": generate_password_hash(pwd)})
    return jsonify({"success": True, "message": "รีเซ็ตรหัสผ่านเรียบร้อย"})

@app.route("/api/superadmin/dorms/<dorm_id>/delete", methods=["POST"])
def superadmin_delete_dorm(dorm_id):
    if not session.get("is_superadmin"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    doc = dorm_ref(dorm_id).get()
    if not doc.exists:
        return jsonify({"success": False, "message": "ไม่พบหอพักนี้"}), 404
    # ลบข้อมูลย่อย (ห้อง + บิล) ก่อน แล้วค่อยลบตัวหอ
    for sub in ["rooms", "invoices"]:
        for d in dorm_ref(dorm_id).collection(sub).stream():
            d.reference.delete()
    dorm_ref(dorm_id).delete()
    return jsonify({"success": True, "message": "ลบหอพักและข้อมูลทั้งหมดเรียบร้อย"})

@app.route("/api/superadmin/stats", methods=["GET"])
def superadmin_stats():
    if not session.get("is_superadmin"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    dorms = list(db.collection("dorms").stream())
    total_invoices, total_paid, total_waiting = 0, 0.0, 0
    for d in dorms:
        for inv in dorm_ref(d.id).collection("invoices").stream():
            st = inv.to_dict().get("status")
            total_invoices += 1
            if st == "paid":
                total_paid += float(inv.to_dict().get("total_amount", 0))
            if st == "waiting_confirm":
                total_waiting += 1
    revenue = 0.0
    for p in db.collection("payments").stream():
        revenue += float(p.to_dict().get("amount", 0))
    return jsonify({"success": True, "dorm_count": len(dorms),
                    "total_invoices": total_invoices, "total_waiting": total_waiting,
                    "total_paid": round(total_paid, 2),
                    "platform_revenue": round(revenue, 2)})

# ============================================================
# เจ้าของหอ (Dorm Owner)
# ============================================================
@app.route("/dorm/login")
def dorm_login_page():
    return render_template("dorm_login.html")

@app.route("/dorm/admin")
def dorm_admin_page():
    dorm_id, dorm = get_current_dorm(allow_expired=True)
    if not dorm_id:
        return redirect("/dorm/login")
    return render_template("dorm_admin.html", dorm=dorm)

@app.route("/api/dorm/login", methods=["POST"])
@limiter.limit("5 per minute")
def dorm_login():
    session.clear()  # 🔒 ล้าง session เก่า
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    docs = list(db.collection("dorms").where("username", "==", username).limit(1).stream())
    if not docs:
        return jsonify({"success": False, "message": "username หรือรหัสผ่านไม่ถูกต้อง"}), 401
    doc = docs[0]
    dorm = doc.to_dict()
    stored = dorm.get("password_hash", "")
    # 🔒 FIX: constant-time comparison for legacy plaintext passwords
    # (old accounts created before hashing was added). Hashed accounts
    # already go through check_password_hash, which is constant-time.
    if stored.startswith(("scrypt:", "pbkdf2:")):
        valid = check_password_hash(stored, password)
    else:
        valid = hmac.compare_digest(stored.encode(), password.encode())
    if not valid:
        return jsonify({"success": False, "message": "username หรือรหัสผ่านไม่ถูกต้อง"}), 401
    if not dorm.get("is_active", True):
        return jsonify({"success": False, "message": "หอพักนี้ถูกระงับ กรุณาติดต่อผู้ให้บริการ"}), 403
    session["dorm_id"] = doc.id
    session.permanent = True
    if is_dorm_expired(dorm):
        return jsonify({"success": True, "message": "เข้าสู่ระบบสำเร็จ", "locked": True})
    return jsonify({"success": True, "message": "เข้าสู่ระบบสำเร็จ"})

@app.route("/api/dorm/register", methods=["POST"])
@limiter.limit("5 per minute")
def dorm_register():
    session.clear()  # 🔒 ล้าง session เก่า
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    name = (data.get("name") or "").strip()
    promptpay_num = (data.get("promptpay_number") or "").strip()
    try:
        water_rate = float(data.get("water_rate") or 0)
        elec_rate = float(data.get("elec_rate") or 0)
    except ValueError:
        return jsonify({"success": False, "message": "เรทน้ำ/ไฟ ต้องเป็นตัวเลข"}), 400
    if len(username) < 3:
        return jsonify({"success": False, "message": "Username ต้องอย่างน้อย 3 ตัวอักษร"}), 400
    if len(password) < 4:
        return jsonify({"success": False, "message": "รหัสผ่านต้องอย่างน้อย 4 ตัวอักษร"}), 400
    if not name:
        return jsonify({"success": False, "message": "กรอกชื่อหอพัก"}), 400
    if len(promptpay_num) < 9:
        return jsonify({"success": False, "message": "กรอกเลขพร้อมเพย์ให้ถูกต้อง"}), 400
    if water_rate <= 0 or elec_rate <= 0:
        return jsonify({"success": False, "message": "เรทน้ำ/ไฟ ต้องมากกว่า 0"}), 400
    if list(db.collection("dorms").where("username", "==", username).limit(1).stream()):
        return jsonify({"success": False, "message": "username นี้ถูกใช้แล้ว"}), 400
    expiry = (date.today() + timedelta(days=TRIAL_DAYS)).isoformat()
    new_ref = db.collection("dorms").document()
    new_ref.set({
        "username": username,
        "password_hash": generate_password_hash(password),
        "name": name,
        "promptpay_number": promptpay_num,
        "water_rate": water_rate,
        "elec_rate": elec_rate,
        "slipok_api_key": "",
        "slipok_branch_id": "",
        "line_access_token": "",
        "line_channel_secret": "",
        "line_webhook_token": "",
        "owner_line_user_id": "",
        "addon_autocheck_active": False,
        "addon_autocheck_credits": 0,
        "expiry_date": expiry,
        "is_active": True,
        "created_at": firestore.SERVER_TIMESTAMP
    })
    session["dorm_id"] = new_ref.id
    session.permanent = True
    return jsonify({"success": True, "message": "สมัครสำเร็จ! ทดลองฟรี 30 วัน"})

@app.route("/api/dorm/logout", methods=["POST"])
def dorm_logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/dorm/me", methods=["GET"])
def dorm_me():
    dorm_id = session.get("dorm_id")
    if not dorm_id:
        return jsonify({"success": False, "message": "ยังไม่ได้เข้าสู่ระบบ"}), 401
    doc = dorm_ref(dorm_id).get()
    if not doc.exists:
        return jsonify({"success": False, "message": "ไม่พบหอ"}), 404
    dorm = doc.to_dict()
    dorm.pop("password_hash", None)
    dorm["id"] = dorm_id
    dorm["is_locked"] = (not dorm.get("is_active", True)) or is_dorm_expired(dorm)
    return jsonify({"success": True, "dorm": dorm})

@app.route("/api/dorm/config", methods=["GET", "POST"])
def dorm_config():
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        try:
            new_config = {
                "name": (data.get("name") or "").strip(),
                "promptpay_number": (data.get("promptpay_number") or "").strip(),
                "water_rate": float(data.get("water_rate") or 0),
                "elec_rate": float(data.get("elec_rate") or 0),
                "contact_info": (data.get("contact_info") or "").strip(),
            }
        except ValueError:
            return jsonify({"success": False, "message": "เรทน้ำ/ไฟ ต้องเป็นตัวเลข"}), 400
        if not new_config["name"] or len(new_config["promptpay_number"]) < 9 or new_config["water_rate"] <= 0 or new_config["elec_rate"] <= 0:
            return jsonify({"success": False, "message": "กรอกข้อมูลไม่ครบ (ชื่อหอ, พร้อมเพย์, เรทน้ำ/ไฟ)"}), 400
        dorm_ref(dorm_id).update(new_config)
        return jsonify({"success": True, "message": "บันทึกการตั้งค่าเรียบร้อย"})
    doc = dorm_ref(dorm_id).get()
    dorm = doc.to_dict() if doc.exists else {}
    dorm.pop("password_hash", None)
    return jsonify({"success": True, "config": dorm})

@app.route("/api/dorm/rooms", methods=["GET", "POST"])
def dorm_rooms():
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        room_no = (data.get("room_no") or "").strip()
        tenant_name = (data.get("tenant_name") or "").strip()
        phone = (data.get("phone") or "").strip()
        line_user_id = (data.get("line_user_id") or "").strip()
        try:
            rent_amount = float(data.get("rent_amount") or 0)
            water_meter = float(data.get("water_meter") or 0)
            elec_meter = float(data.get("elec_meter") or 0)
            deposit_amount = float(data.get("deposit_amount") or 0)
            garbage_fee = float(data.get("garbage_fee") or 0)
            service_fee = float(data.get("service_fee") or 0)
        except ValueError:
            return jsonify({"success": False, "message": "ตัวเลขไม่ถูกต้อง"}), 400
        if not room_no:
            return jsonify({"success": False, "message": "กรอกเลขห้อง"}), 400
        if rent_amount <= 0:
            return jsonify({"success": False, "message": "ค่าเช่าต้องมากกว่า 0"}), 400
        if water_meter < 0 or elec_meter < 0:
            return jsonify({"success": False, "message": "มิเตอร์ติดลบไม่ได้"}), 400
        for r in dorm_ref(dorm_id).collection("rooms").stream():
            if r.to_dict().get("room_no") == room_no:
                return jsonify({"success": False, "message": "เลขห้องนี้มีอยู่แล้ว"}), 400
        extra_fees = parse_extra_fees(data.get("extra_fees"))
        room_ref = dorm_ref(dorm_id).collection("rooms").document()
        room_ref.set({
            "room_no": room_no, "tenant_name": tenant_name, "phone": phone,
            "line_user_id": line_user_id, "rent_amount": rent_amount,
            "water_meter": water_meter, "elec_meter": elec_meter,
            "deposit_amount": deposit_amount, "deposit_status": "none",
            "garbage_fee": garbage_fee, "service_fee": service_fee,
            "extra_fees": extra_fees,
            "active": True, "created_at": firestore.SERVER_TIMESTAMP
        })
        return jsonify({"success": True, "message": f"เพิ่มห้อง {room_no} เรียบร้อย", "room_id": room_ref.id})
    rooms = [{"id": r.id, **r.to_dict()} for r in dorm_ref(dorm_id).collection("rooms").stream()]
    rooms.sort(key=lambda x: str(x.get("room_no")))
    return jsonify({"success": True, "rooms": rooms})

@app.route("/api/dorm/rooms/<room_id>", methods=["DELETE"])
def dorm_delete_room(room_id):
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    dorm_ref(dorm_id).collection("rooms").document(room_id).delete()
    return jsonify({"success": True, "message": "ลบห้องเรียบร้อย"})

@app.route("/api/dorm/rooms/<room_id>/edit", methods=["POST"])
def dorm_edit_room(room_id):
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    doc = dorm_ref(dorm_id).collection("rooms").document(room_id).get()
    if not doc.exists:
        return jsonify({"success": False, "message": "ไม่พบห้อง"}), 404
    data = request.get_json(silent=True) or {}
    try:
        rent_amount = float(data.get("rent_amount") or 0)
        deposit_amount = float(data.get("deposit_amount") or 0)
        garbage_fee = float(data.get("garbage_fee") or 0)
        service_fee = float(data.get("service_fee") or 0)
    except ValueError:
        return jsonify({"success": False, "message": "ตัวเลขไม่ถูกต้อง"}), 400
    extra_fees = parse_extra_fees(data.get("extra_fees"))
    update = {
        "tenant_name": (data.get("tenant_name") or "").strip(),
        "phone": (data.get("phone") or "").strip(),
        "line_user_id": (data.get("line_user_id") or "").strip(),
        "rent_amount": rent_amount,
        "deposit_amount": deposit_amount,
        "garbage_fee": garbage_fee,
        "service_fee": service_fee,
        "extra_fees": extra_fees,
    }
    ds = (data.get("deposit_status") or "").strip()
    if ds in ("none", "received", "returned"):
        update["deposit_status"] = ds
    dorm_ref(dorm_id).collection("rooms").document(room_id).update(update)
    return jsonify({"success": True, "message": "แก้ไขห้องเรียบร้อย"})

@app.route("/api/dorm/rooms/bulk_fees", methods=["POST"])
def dorm_rooms_bulk_fees():
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    try:
        garbage_fee = float(data.get("garbage_fee") or 0)
        service_fee = float(data.get("service_fee") or 0)
    except ValueError:
        return jsonify({"success": False, "message": "ตัวเลขไม่ถูกต้อง"}), 400
    updated = 0
    for doc in dorm_ref(dorm_id).collection("rooms").stream():
        if not doc.to_dict().get("active", True):
            continue
        dorm_ref(dorm_id).collection("rooms").document(doc.id).update({
            "garbage_fee": garbage_fee, "service_fee": service_fee})
        updated += 1
    return jsonify({"success": True, "message": f"ตั้งค่าขยะ/ค่าส่วนกลางให้ทุกห้อง ({updated} ห้อง) เรียบร้อย"})

@app.route("/api/dorm/invoices/generate", methods=["POST"])
def dorm_generate_invoices():
    dorm_id, dorm = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    if not dorm.get("promptpay_number"):
        return jsonify({"success": False, "message": "ยังไม่ได้ตั้งค่าหอพักก่อน"}), 400
    data = request.get_json(silent=True) or {}
    try:
        month, year = int(data.get("month")), int(data.get("year"))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "เดือน/ปี ไม่ถูกต้อง"}), 400
    if not (1 <= month <= 12) or year < 2020:
        return jsonify({"success": False, "message": "เดือน/ปี ไม่ถูกต้อง"}), 400
    meters = data.get("meters") or {}
    created, errors = 0, []
    for doc in dorm_ref(dorm_id).collection("rooms").stream():
        room = doc.to_dict()
        if not room.get("active", True):
            continue
        m = meters.get(doc.id)
        if m is None:
            continue  # 👈 ห้องที่ไม่ได้เลือก (ไม่มีใน meters) = ข้าม ไม่สร้างบิล
        inv_id = f"{dorm_id}_{room.get('room_no')}_{month}_{year}"
        if dorm_ref(dorm_id).collection("invoices").document(inv_id).get().exists:
            errors.append(f"ห้อง {room.get('room_no')}: มีบิลเดือนนี้แล้ว")
            continue
        try:
            new_water, new_elec = float(m["water"]), float(m["elec"])
        except (TypeError, KeyError, ValueError):
            errors.append(f"ห้อง {room.get('room_no')}: กรอกเลขมิเตอร์ไม่ครบ")
            continue
        water_usage = max(0, new_water - float(room.get("water_meter") or 0))
        elec_usage = max(0, new_elec - float(room.get("elec_meter") or 0))
        water_cost = round(water_usage * float(dorm.get("water_rate") or 0), 2)
        elec_cost = round(elec_usage * float(dorm.get("elec_rate") or 0), 2)
        rent = float(room.get("rent_amount") or 0)
        garbage_fee = float(room.get("garbage_fee") or 0)
        service_fee = float(room.get("service_fee") or 0)
        extra_fees = room.get("extra_fees") or []
        extra_total = round(sum(float(f.get("amount") or 0) for f in extra_fees), 2)
        total = round(water_cost + elec_cost + rent + garbage_fee + service_fee + extra_total, 2)
        dorm_ref(dorm_id).collection("rooms").document(doc.id).update(
            {"water_meter": new_water, "elec_meter": new_elec})
        dorm_ref(dorm_id).collection("invoices").document(inv_id).set({
            "dorm_id": dorm_id, "month": month, "year": year, "room_id": doc.id,
            "room_no": room.get("room_no"), "tenant_name": room.get("tenant_name", ""),
            "water_usage": water_usage, "elec_usage": elec_usage,
            "water_cost": water_cost, "elec_cost": elec_cost,
            "rent_amount": rent, "garbage_fee": garbage_fee, "service_fee": service_fee,
            "extra_fees": extra_fees,
            "total_amount": total,
            "status": "pending", "bill_token": secrets.token_urlsafe(32),
            "trans_ref": "", "slip_image": "", "slip_filename": "",
            "prev_water_meter": float(room.get("water_meter") or 0),
            "prev_elec_meter": float(room.get("elec_meter") or 0),
            "created_at": firestore.SERVER_TIMESTAMP, "paid_at": None
        })
        created += 1
    return jsonify({"success": True, "created": created, "errors": errors,
                    "message": f"สร้างบิลสำเร็จ {created} ใบ" +
                    (f" / มีปัญหา: {'; '.join(errors)}" if errors else "")})
                   
@app.route("/api/dorm/invoices/<invoice_id>/edit", methods=["POST"])
def dorm_edit_invoice(invoice_id):
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    doc = dorm_ref(dorm_id).collection("invoices").document(invoice_id).get()
    if not doc.exists:
        return jsonify({"success": False, "message": "ไม่พบบิล"}), 404
    cur = doc.to_dict()
    if cur.get("status") != "pending":
        return jsonify({"success": False, "message": "แก้ไขได้เฉพาะบิลที่ยังรอจ่าย"}), 400
    data = request.get_json(silent=True) or {}
    try:
        rent = float(data.get("rent_amount", cur.get("rent_amount", 0)))
        water_usage = float(data.get("water_usage", cur.get("water_usage", 0)))
        elec_usage = float(data.get("elec_usage", cur.get("elec_usage", 0)))
        garbage_fee = float(data.get("garbage_fee", cur.get("garbage_fee", 0)))
        service_fee = float(data.get("service_fee", cur.get("service_fee", 0)))
    except ValueError:
        return jsonify({"success": False, "message": "ตัวเลขไม่ถูกต้อง"}), 400
    extra_fees = parse_extra_fees(data.get("extra_fees", cur.get("extra_fees")))
    extra_total = round(sum(float(f.get("amount") or 0) for f in extra_fees), 2)
    dorm_doc = dorm_ref(dorm_id).get()
    dorm = dorm_doc.to_dict() if dorm_doc.exists else {}
    water_cost = round(max(0, water_usage) * float(dorm.get("water_rate") or 0), 2)
    elec_cost = round(max(0, elec_usage) * float(dorm.get("elec_rate") or 0), 2)
    total = round(water_cost + elec_cost + rent + garbage_fee + service_fee + extra_total, 2)
    dorm_ref(dorm_id).collection("invoices").document(invoice_id).update({
        "water_usage": max(0, water_usage), "elec_usage": max(0, elec_usage),
        "water_cost": water_cost, "elec_cost": elec_cost,
        "rent_amount": rent, "garbage_fee": garbage_fee, "service_fee": service_fee,
        "extra_fees": extra_fees,
        "total_amount": total
    })
    return jsonify({"success": True, "message": f"แก้ไขบิลเรียบร้อย ยอดรวมใหม่ {total:.2f} บาท"})

@app.route("/api/dorm/invoices/<invoice_id>/cancel", methods=["POST"])
def dorm_cancel_invoice(invoice_id):
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    doc = dorm_ref(dorm_id).collection("invoices").document(invoice_id).get()
    if not doc.exists:
        return jsonify({"success": False, "message": "ไม่พบบิล"}), 404
    cur = doc.to_dict()
    if cur.get("status") != "pending":
        return jsonify({"success": False, "message": "ยกเลิกได้เฉพาะบิลที่ยังรอจ่าย"}), 400
    room_id = cur.get("room_id", "")
    if room_id:
        dorm_ref(dorm_id).collection("rooms").document(room_id).update({
            "water_meter": cur.get("prev_water_meter", 0),
            "elec_meter": cur.get("prev_elec_meter", 0)
        })
    dorm_ref(dorm_id).collection("invoices").document(invoice_id).delete()
    return jsonify({"success": True, "message": "ยกเลิกบิลเรียบร้อย (มิเตอร์คืนค่าเดิมแล้ว) — สร้างใหม่ได้เลย"})

@app.route("/api/dorm/invoices", methods=["GET"])
def dorm_invoices():
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    month, year = request.args.get("month", type=int), request.args.get("year", type=int)
    invoices = []
    for doc in dorm_ref(dorm_id).collection("invoices").stream():
        d = doc.to_dict()
        if month and d.get("month") != month:
            continue
        if year and d.get("year") != year:
            continue
        d["id"] = doc.id
        invoices.append(d)
    invoices.sort(key=lambda x: str(x.get("room_no")))
    return jsonify({"success": True, "invoices": invoices})

@app.route("/api/dorm/invoices/export")
def dorm_invoices_export():
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return "Unauthorized", 401
    month, year = request.args.get("month", type=int), request.args.get("year", type=int)
    rows = []
    for doc in dorm_ref(dorm_id).collection("invoices").stream():
        d = doc.to_dict()
        if month and d.get("month") != month:
            continue
        if year and d.get("year") != year:
            continue
        rows.append([
            sanitize_csv(d.get("room_no")),
            sanitize_csv(d.get("tenant_name", "")),
            d.get("water_usage", 0), d.get("elec_usage", 0),
            d.get("water_cost", 0), d.get("elec_cost", 0),
            d.get("rent_amount", 0), d.get("total_amount", 0),
            d.get("status", "")
        ])
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ห้อง", "ผู้เช่า", "น้ำ(หน่วย)", "ไฟ(หน่วย)", "ค่าน้ำ", "ค่าไฟ", "ค่าเช่า", "รวม", "สถานะ"])
    w.writerows(rows)
    return Response(buf.getvalue().encode("utf-8-sig"), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=bills.csv"})

@app.route("/api/dorm/invoices/<invoice_id>/qr")
def dorm_invoice_qr(invoice_id):
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return "Unauthorized", 401
    doc = dorm_ref(dorm_id).collection("invoices").document(invoice_id).get()
    if not doc.exists:
        return "ไม่พบบิล", 404
    url = request.url_root.rstrip("/") + "/bill/" + doc.to_dict().get("bill_token", "")
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

@app.route("/api/dorm/invoices/<invoice_id>/billcard")
def dorm_invoice_billcard(invoice_id):
    dorm_id, dorm = get_current_dorm()
    if not dorm_id:
        return "Unauthorized", 401
    doc = dorm_ref(dorm_id).collection("invoices").document(invoice_id).get()
    if not doc.exists:
        return "ไม่พบบิล", 404
    inv = doc.to_dict()
    pay_qr = (f"https://promptpay.io/{dorm.get('promptpay_number','')}/"
              f"{_fmt_amount(inv.get('total_amount', 0))}.png")
    link_qr = generate_qr_datauri(request.url_root.rstrip('/') + "/bill/" + inv.get("bill_token", ""))
    return render_template("billcard.html", invoice=inv, dorm=dorm, pay_qr=pay_qr, link_qr=link_qr)

@app.route("/api/dorm/invoices/<invoice_id>/slip")
def dorm_invoice_slip(invoice_id):
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return "Unauthorized", 401
    doc = dorm_ref(dorm_id).collection("invoices").document(invoice_id).get()
    if not doc.exists:
        return "ไม่พบบิล", 404
    b64 = doc.to_dict().get("slip_image", "")
    if not b64:
        return "ยังไม่มีสลิป", 404
    try:
        raw = base64.b64decode(b64)
    except Exception:
        return "สลิปเสียหาย", 400
    return send_file(io.BytesIO(raw), mimetype="image/jpeg")

@app.route("/api/dorm/invoices/<invoice_id>/mark_paid", methods=["POST"])
def dorm_mark_paid_invoice(invoice_id):
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    doc = dorm_ref(dorm_id).collection("invoices").document(invoice_id).get()
    if not doc.exists:
        return jsonify({"success": False, "message": "ไม่พบบิล"}), 404
    cur = doc.to_dict()
    if cur.get("status") != "pending":
        return jsonify({"success": False, "message": "ทำได้เฉพาะบิลที่ยังรอจ่าย"}), 400
    dorm_ref(dorm_id).collection("invoices").document(invoice_id).update({
        "status": "paid",
        "paid_at": firestore.SERVER_TIMESTAMP,
        "payment_method": "cash",
    })
    return jsonify({"success": True, "message": "บันทึกจ่ายแล้ว (เงินสด/จ่ายตรง) เรียบร้อย"})

@app.route("/api/dorm/invoices/<invoice_id>/approve", methods=["POST"])
def dorm_approve_invoice(invoice_id):
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    res = execute_approve_invoice_transaction(
        db.transaction(), dorm_ref(dorm_id).collection("invoices").document(invoice_id))
    return (jsonify({"success": True, "message": "อนุมัติแล้ว บิลนี้จ่ายแล้ว"})
            if res["success"] else jsonify({"success": False, "message": res["message"]}), 400)

@app.route("/api/dorm/invoices/<invoice_id>/reject", methods=["POST"])
def dorm_reject_invoice(invoice_id):
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    res = execute_reject_invoice_transaction(
        db.transaction(), dorm_ref(dorm_id).collection("invoices").document(invoice_id))
    return (jsonify({"success": True, "message": "ปฏิเสธสลิปแล้ว ผู้เช่าส่งใหม่ได้"})
            if res["success"] else jsonify({"success": False, "message": res["message"]}), 400)

@app.route("/api/dorm/invoices/<invoice_id>/send_line", methods=["POST"])
def dorm_send_line(invoice_id):
    dorm_id, dorm = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    token = dorm.get("line_access_token")
    if not token:
        return jsonify({"success": False, "message": "ยังไม่ได้ตั้งค่า LINE Access Token (ดูคู่มือในหน้า Admin)"}), 400
    doc = dorm_ref(dorm_id).collection("invoices").document(invoice_id).get()
    if not doc.exists:
        return jsonify({"success": False, "message": "ไม่พบบิล"}), 404
    d = doc.to_dict()
    room_doc = dorm_ref(dorm_id).collection("rooms").document(d.get("room_id", "")).get()
    line_uid = (room_doc.to_dict() or {}).get("line_user_id") if room_doc.exists else None
    if not line_uid:
        return jsonify({"success": False, "message": "ห้องนี้ยังไม่ได้กรอก LINE User ID"}), 400
    bill_url = request.url_root.rstrip("/") + "/bill/" + d.get("bill_token", "")
    text = (f"📄 บิลค่าเช่า {dorm.get('name','หอพัก')} เดือน {d.get('month')}/{d.get('year')}\n"
            f"ห้อง {d.get('room_no')} ยอดรวม {d.get('total_amount')} บาท\n"
            f"กดดูบิลและชำระ: {bill_url}")
    r = requests.post("https://api.line.me/v2/bot/message/push",
                      headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                      json={"to": line_uid, "messages": [{"type": "text", "text": text}]}, timeout=10)
    print("--- LINE PUSH:", r.status_code, r.text)
    if r.status_code != 200:
        return jsonify({"success": False, "message": f"LINE ส่งไม่สำเร็จ ({r.status_code})"}), 400
    return jsonify({"success": True, "message": "ส่ง LINE เรียบร้อย"})

# ============================================================
# Add-on ตรวจสลิปอัตโนมัติ + ต่ออายุ
# ============================================================
@app.route("/api/dorm/addon", methods=["GET"])
def dorm_addon_status():
    dorm_id, dorm = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    return jsonify({"success": True,
                    "active": bool(dorm.get("addon_autocheck_active")),
                    "credits": dorm.get("addon_autocheck_credits", 0),
                    "fee": ADDON_FEE, "quota": ADDON_CREDITS})

@app.route("/api/dorm/platform_qr", methods=["GET"])
def dorm_platform_qr():
    dorm_id, _ = get_current_dorm(allow_expired=True)
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    t = request.args.get("type", "renewal")
    if t not in ("renewal", "addon"):
        return jsonify({"success": False, "message": "type ไม่ถูกต้อง"}), 400
    fee = SYSTEM_FEE if t == "renewal" else ADDON_FEE
    if not PLATFORM_PROMPTPAY:
        return jsonify({"success": False, "message": "ยังไม่ได้ตั้งค่า PLATFORM_PROMPTPAY ใน Render Secrets"}), 500
    qr = f"https://promptpay.io/{PLATFORM_PROMPTPAY}/{_fmt_amount(fee)}.png"
    return jsonify({"success": True, "qr": qr, "amount": fee, "promptpay": PLATFORM_PROMPTPAY})

@app.route("/api/dorm/platform_pay", methods=["POST"])
@limiter.limit("5 per minute")
def dorm_platform_pay():
    dorm_id, _ = get_current_dorm(allow_expired=True)
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    t = request.form.get("type", "renewal")
    if t not in ("renewal", "addon"):
        return jsonify({"success": False, "message": "type ไม่ถูกต้อง"}), 400
    if "file" not in request.files:
        return jsonify({"success": False, "message": "กรุณาแนบไฟล์สลิป"}), 400
    fee = SYSTEM_FEE if t == "renewal" else ADDON_FEE
    if not PLATFORM_SLIPOK_KEY or not PLATFORM_SLIPOK_BRANCH:
        return jsonify({"success": False, "message": "ยังไม่ได้ตั้งค่า SlipOK แพลตฟอร์ม"}), 500
    res = verify_platform_slip(request.files["file"], float(fee))
    if not res["success"]:
        return jsonify({"success": False, "message": res["message"]}), 400
    if not mark_slip_used(res["trans_ref"], res["amount"], f"{t}:{dorm_id}"):
        return jsonify({"success": False, "message": "สลิปนี้เคยถูกใช้งานแล้ว"}), 400
    if t == "renewal":
        new_exp = (date.today() + timedelta(days=30)).isoformat()
        dorm_ref(dorm_id).update({"expiry_date": new_exp})
        msg = f"ต่ออายุสำเร็จ! ใช้งานได้ถึง {new_exp}"
    else:
        dorm_ref(dorm_id).update({"addon_autocheck_active": True,
                                  "addon_autocheck_credits": ADDON_CREDITS})
        msg = f"เปิดตรวจสลิปอัตโนมัติแล้ว! ได้ {ADDON_CREDITS} ครั้ง"
    db.collection("payments").add({"dorm_id": dorm_id, "type": t, "amount": fee,
                                   "created_at": firestore.SERVER_TIMESTAMP})
    return jsonify({"success": True, "message": msg})

# ============================================================
# LINE Webhook (ขั้นสูง)
# ============================================================
@app.route("/api/dorm/webhook_info", methods=["GET"])
def dorm_webhook_info():
    dorm_id, dorm = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    token = dorm.get("line_webhook_token", "")
    if not token:
        token = secrets.token_urlsafe(24)
        dorm_ref(dorm_id).update({"line_webhook_token": token})
    webhook_url = request.url_root.rstrip("/") + "/api/line/webhook/" + token
    # 🔒 FIX: no longer return the raw Channel Secret to the browser —
    # only whether it's set, same pattern as line_access_token_set below.
    return jsonify({"success": True, "webhook_url": webhook_url,
                    "line_channel_secret_set": bool(dorm.get("line_channel_secret")),
                    "owner_line_user_id": dorm.get("owner_line_user_id", ""),
                    "line_access_token_set": bool(dorm.get("line_access_token"))})

@app.route("/api/dorm/webhook_config", methods=["POST"])
def dorm_webhook_config():
    dorm_id, _ = get_current_dorm()
    if not dorm_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    update = {}
    secret = (data.get("line_channel_secret") or "").strip()
    token = (data.get("line_access_token") or "").strip()
    if secret:
        update["line_channel_secret"] = secret
    if token:
        update["line_access_token"] = token
    if not update:
        return jsonify({"success": False, "message": "ไม่มีข้อมูลให้บันทึก"}), 400
    dorm_ref(dorm_id).update(update)
    return jsonify({"success": True, "message": "บันทึกการตั้งค่า LINE เรียบร้อย"})

@app.route("/api/line/webhook/<token>", methods=["POST"])
def line_webhook(token):
    docs = list(db.collection("dorms").where("line_webhook_token", "==", token).limit(1).stream())
    if not docs:
        return "Not Found", 404
    dorm_doc = docs[0]
    dorm = dorm_doc.to_dict()
    body = request.get_data()
    secret = dorm.get("line_channel_secret", "")
    # 🔒 FIX: previously, if a dorm hadn't set a Channel Secret yet, the
    # signature check was skipped entirely — meaning anyone who guessed
    # or leaked the webhook token could POST fake events. Now we reject
    # instead of skipping.
    if not secret:
        return "Webhook not configured", 403
    sig = base64.b64encode(hmac.new(secret.encode(), body, hashlib.sha256).digest()).decode()
    if not hmac.compare_digest(sig, request.headers.get("x-line-signature", "")):
        return "Invalid signature", 403
    payload = request.json or {}
    access_token = dorm.get("line_access_token", "")
    for ev in payload.get("events", []):
        user_id = (ev.get("source") or {}).get("userId")
        reply_token = ev.get("replyToken")
        if user_id:
            dorm_ref(dorm_doc.id).update({"owner_line_user_id": user_id})
        if user_id and reply_token and access_token:
            text = ("✅ เชื่อมต่อระบบเรียบร้อย!\n"
                    "LINE ID ของคุณ (เอาไปใส่ช่อง Owner LINE User ID):\n" + user_id)
            try:
                requests.post("https://api.line.me/v2/bot/message/reply",
                              headers={"Authorization": "Bearer " + access_token,
                                       "Content-Type": "application/json"},
                              json={"replyToken": reply_token,
                                    "messages": [{"type": "text", "text": text}]}, timeout=10)
            except Exception:
                pass
    return "OK", 200

# ============================================================
# หน้าบิลสำหรับผู้เช่า
# ============================================================
@app.route("/bill/<bill_token>")
def bill_page(bill_token):
    inv = find_invoice_by_token(bill_token)
    if not inv:
        return "ไม่พบบิล หรือลิงก์ไม่ถูกต้อง", 404
    dorm_doc = dorm_ref(inv["dorm_id"]).get()
    dorm = dorm_doc.to_dict() if dorm_doc.exists else {}
    if not dorm.get("is_active", True) or is_dorm_expired(dorm):
        return "หอพักนี้ปิดให้บริการชั่วคราว กรุณาติดต่อเจ้าของหอ", 403
    pay_qr = (f"https://promptpay.io/{dorm.get('promptpay_number','')}/"
              f"{_fmt_amount(inv['data'].get('total_amount', 0))}.png")
    return render_template("bill.html", invoice=inv["data"], dorm=dorm, pay_qr=pay_qr)

@app.route("/bill/<bill_token>/pay", methods=["POST"])
@limiter.limit("5 per minute")
def bill_pay(bill_token):
    inv = find_invoice_by_token(bill_token)
    if not inv:
        return jsonify({"success": False, "message": "ไม่พบบิล"}), 404
    dorm_doc = dorm_ref(inv["dorm_id"]).get()
    if not dorm_doc.exists:
        return jsonify({"success": False, "message": "หอพักนี้ไม่พร้อมใช้งาน"}), 400
    dorm = dorm_doc.to_dict()
    if not dorm.get("is_active", True) or is_dorm_expired(dorm):
        return jsonify({"success": False, "message": "หอพักนี้ปิดให้บริการชั่วคราว"}), 403
    invoice_ref = dorm_ref(inv["dorm_id"]).collection("invoices").document(inv["id"])
    data = inv["data"]
    if data.get("status") == "paid":
        return jsonify({"success": False, "message": "บิลนี้ชำระแล้ว"}), 400
    if data.get("status") == "waiting_confirm":
        return jsonify({"success": False, "message": "บิลนี้รอการตรวจสอบจากเจ้าของหออยู่"}), 400
    if "file" not in request.files:
        return jsonify({"success": False, "message": "กรุณาแนบไฟล์สลิป"}), 400
    file = request.files["file"]

    # ===== โหมดอัตโนมัติ: ซื้อ add-on + ตั้งสาขาแล้ว =====
    can_auto = (dorm.get("slipok_branch_id")
                and dorm.get("slipok_api_key")
                and dorm.get("addon_autocheck_active")
                and dorm.get("addon_autocheck_credits", 0) > 0)
    if can_auto:
        url = f"https://api.slipok.com/api/line/apikey/{dorm.get('slipok_branch_id')}"
        headers = {"x-authorization": dorm.get("slipok_api_key")}
        files = {"files": (file.filename or "slip.jpg", file.stream, file.mimetype or "image/jpeg")}
        try:
            resp = requests.post(url, headers=headers, files=files, data={"log": True}, timeout=15)
            res = resp.json()
        except Exception as e:
            return jsonify({"success": False, "message": "ตรวจสลิปผิดพลาด กรุณาลองใหม่"}), 502
        print(f"--- SLIPOK RESPONSE: {res} ---")
        if not res.get("success"):
            return jsonify({"success": False, "message": res.get("message", "สลิปไม่ถูกต้อง")}), 400
        d = res.get("data", {})
        trans_ref, amount = d.get("transRef"), float(d.get("amount", 0))
        if not trans_ref or amount <= 0:
            return jsonify({"success": False, "message": "ข้อมูลสลิปไม่สมบูรณ์"}), 400
        if abs(amount - float(data.get("total_amount"))) > 0.01:
            return jsonify({"success": False, "message": f"ยอดไม่ตรงบิล (บิล {data.get('total_amount')} บาท / โอน {amount} บาท)"}), 400
        if not slip_is_fresh(d.get("transDate"), d.get("transTime")):
            return jsonify({"success": False, "message": "สลิปเก่าเกินไป (ต้องโอนภายใน 15 นาทีที่ผ่านมา) กรุณาโอนใหม่"}), 400
        res = execute_mark_paid_transaction(db.transaction(), invoice_ref,
                                            db.collection("used_slips").document(trans_ref), trans_ref, amount)
        if not res["success"]:
            return jsonify({"success": False, "message": res["message"]}), 400
        dorm_ref(inv["dorm_id"]).update({"addon_autocheck_credits": Increment(-1)})
        return jsonify({"success": True, "message": "ชำระเงินสำเร็จ! บิลนี้จ่ายแล้ว", "status": "paid"})

    # ===== โหมดตรวจมือ =====
    file.seek(0)
    slip_b64 = compress_slip(file)
    res = execute_mark_waiting_transaction(db.transaction(), invoice_ref, slip_b64, file.filename or "slip.jpg")
    if not res["success"]:
        return jsonify({"success": False, "message": res["message"]}), 400
    return jsonify({"success": True, "message": "ส่งสลิปเรียบร้อย รอเจ้าของหอตรวจสอบ", "status": "waiting_confirm"})

# ============================================================
# Security Headers
# ============================================================
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# ============================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
