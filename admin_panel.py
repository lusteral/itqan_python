import os
import time
import secrets
import hashlib
import hmac
import html
from flask import Blueprint, render_template, request, redirect, session, flash, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import get_db

ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg',
    'mp4', 'webm', 'ogg', 'mov', 'mkv',
    'pdf', 'zip', 'rar', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'txt'
}
BLOCKED_EXTENSIONS = {'py', 'pyc', 'exe', 'bat', 'cmd', 'sh', 'php', 'js', 'html', 'htm', 'dll', 'so'}


def save_uploaded_file(file_storage, prefix, upload_folder):
    """حفظ الملف المرفوع بشكل آمن بعد فحص الامتداد"""
    if not file_storage or not file_storage.filename:
        return None
    orig_name = file_storage.filename
    ext = os.path.splitext(orig_name)[1].lower().lstrip('.')
    if not ext or ext in BLOCKED_EXTENSIONS or ext not in ALLOWED_EXTENSIONS:
        return None
    safe_token = secrets.token_hex(4)
    filename = f"{prefix}_{int(time.time())}_{safe_token}.{ext}"
    os.makedirs(upload_folder, exist_ok=True)
    file_storage.save(os.path.join(upload_folder, filename))
    return filename


def remove_uploaded_file(filename, upload_folder):
    """حذف ملف مرفوع من المجلد بأمان"""
    if not filename or filename.startswith('http'):
        return
    safe_name = os.path.basename(filename)
    fpath = os.path.join(upload_folder, safe_name)
    if os.path.exists(fpath):
        try:
            os.remove(fpath)
        except Exception:
            pass


def get_client_fingerprint():
    ua = request.headers.get('User-Agent', 'unknown')
    return hashlib.sha256(ua.encode('utf-8')).hexdigest()


def ensure_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def verify_csrf():
    token = request.form.get('csrf_token', '')
    expected = session.get('csrf_token', '')
    if not token or not expected:
        return False
    return hmac.compare_digest(str(token), str(expected))


def is_admin_authenticated():
    if not session.get('is_admin') or not session.get('admin_id'):
        return False
    if session.get('admin_fp') != get_client_fingerprint():
        return False
    last_active = session.get('admin_last_active', 0)
    if time.time() - last_active > 7200:  # ساعتان مهلة عدم النشاط
        return False
    conn = get_db()
    adm = conn.execute('SELECT id, username, full_name, role FROM admins WHERE id=?', (session['admin_id'],)).fetchone()
    conn.close()
    if not adm:
        return False
    session['admin_last_active'] = time.time()
    session['admin_username'] = adm['username']
    session['admin_name'] = adm['full_name']
    session['admin_role'] = adm['role']
    return True


def render_pure_white_login(error_msg, csrf_token, login_action):
    """شاشة تسجيل دخول بخلفية بيضاء كاملة وحقل اسم المستخدم وكلمة المرور فقط بدون أي عناصر أخرى"""
    err_html = f'<div class="text-rose-600 text-xs font-bold text-center bg-rose-50 border border-rose-200 rounded-xl p-2.5">{html.escape(error_msg)}</div>' if error_msg else ''
    html_page = f'''<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تسجيل الدخول</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800;900&display=swap" rel="stylesheet">
    <style>
        html, body {{
            font-family: 'Tajawal', sans-serif;
            background-color: #FFFFFF !important;
            margin: 0;
            padding: 0;
            min-height: 100vh;
        }}
    </style>
</head>
<body class="bg-white min-h-screen flex items-center justify-center p-4">
    <form method="POST" action="{login_action}" autocomplete="off" class="w-full max-w-xs space-y-3 bg-white">
        <input type="hidden" name="csrf_token" value="{csrf_token}">
        {err_html}
        <div>
            <input type="text" name="username" placeholder="اسم المستخدم" required autofocus
                   class="w-full px-4 py-3 border border-slate-300 rounded-xl text-sm font-bold text-slate-900 bg-white outline-none focus:border-slate-900 transition">
        </div>
        <div>
            <input type="password" name="password" placeholder="كلمة المرور" required
                   class="w-full px-4 py-3 border border-slate-300 rounded-xl text-sm font-bold text-slate-900 bg-white outline-none focus:border-slate-900 transition">
        </div>
        <button type="submit"
                class="w-full py-3 bg-slate-900 hover:bg-slate-800 text-white font-black rounded-xl text-sm transition cursor-pointer">
            دخول
        </button>
    </form>
</body>
</html>'''
    resp = make_response(html_page)
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return resp


def register_admin_routes(app, url_prefix='', site_url='/', blueprint_name='admin_bp', upload_folder=None):
    if upload_folder is None:
        base_d = os.path.dirname(os.path.abspath(__file__))
        upload_folder = os.path.join(base_d, 'uploads')
    os.makedirs(upload_folder, exist_ok=True)

    bp = Blueprint(blueprint_name, __name__)
    base_url = url_prefix.rstrip('/') if url_prefix else ''

    def redirect_tab(tab_name='overview', msg=None, msg_type='success'):
        if msg:
            session['admin_flash_msg'] = msg
            session['admin_flash_type'] = msg_type
        target = f"{base_url}/?tab={tab_name}" if base_url else f"/?tab={tab_name}"
        return redirect(target)

    @bp.after_request
    def add_security_headers(response):
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response

    @bp.route('/login', methods=['GET', 'POST'])
    def login():
        if is_admin_authenticated():
            return redirect(f"{base_url}/" if base_url else "/")

        error_msg = ""
        client_ip = request.remote_addr or '127.0.0.1'
        conn = get_db()

        # فحص الحماية من التخمين (Brute-Force Protection)
        attempt_row = conn.execute('SELECT * FROM login_attempts WHERE ip_address=?', (client_ip,)).fetchone()
        now = time.time()
        if attempt_row and attempt_row['locked_until'] > now:
            rem = int(attempt_row['locked_until'] - now)
            conn.close()
            error_msg = f"تم قفل المحاولات مؤقتاً للأمان. حاول بعد {rem} ثانية."
            return render_pure_white_login(error_msg, ensure_csrf_token(), f"{base_url}/login")

        if request.method == 'POST':
            if not verify_csrf():
                conn.close()
                error_msg = "انتهت صلاحية الجلسة، يرجى المحاولة مرة أخرى."
                return render_pure_white_login(error_msg, ensure_csrf_token(), f"{base_url}/login")

            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()

            adm = conn.execute('SELECT * FROM admins WHERE username=?', (username,)).fetchone()
            if adm and check_password_hash(adm['password_hash'], password):
                # تصفير محاولات الفشل
                conn.execute('DELETE FROM login_attempts WHERE ip_address=?', (client_ip,))
                conn.execute('UPDATE admins SET last_login=CURRENT_TIMESTAMP WHERE id=?', (adm['id'],))
                conn.commit()
                conn.close()

                session.clear()
                session['is_admin'] = 1
                session['admin_id'] = adm['id']
                session['admin_username'] = adm['username']
                session['admin_name'] = adm['full_name']
                session['admin_role'] = adm['role']
                session['admin_fp'] = get_client_fingerprint()
                session['admin_last_active'] = time.time()
                session['csrf_token'] = secrets.token_hex(32)
                return redirect(f"{base_url}/" if base_url else "/")
            else:
                # تسجيل محاولة فاشلة
                cur_attempts = (attempt_row['attempts'] if attempt_row else 0) + 1
                locked_until = (now + 300) if cur_attempts >= 5 else 0
                conn.execute('''INSERT INTO login_attempts (ip_address, attempts, locked_until)
                                VALUES (?, ?, ?)
                                ON CONFLICT(ip_address) DO UPDATE SET attempts=?, locked_until=?''',
                             (client_ip, cur_attempts, locked_until, cur_attempts, locked_until))
                conn.commit()
                conn.close()
                if locked_until > now:
                    error_msg = "تم تجاوز الحد المسموح (5 محاولات). تم القفل لمدة 5 دقائق."
                else:
                    rem_tries = 5 - cur_attempts
                    error_msg = f"اسم المستخدم أو كلمة المرور غير صحيحة ({rem_tries} محاولات متبقية)"
                return render_pure_white_login(error_msg, ensure_csrf_token(), f"{base_url}/login")

        conn.close()
        return render_pure_white_login(error_msg, ensure_csrf_token(), f"{base_url}/login")

    @bp.route('/logout')
    def logout():
        session.clear()
        return redirect(f"{base_url}/login")

    # ================= الصفحة الرئيسية للوحة التحكم الشاملة =================
    @bp.route('/')
    def dashboard():
        if not is_admin_authenticated():
            return redirect(f"{base_url}/login")

        csrf = ensure_csrf_token()
        flash_msg = session.pop('admin_flash_msg', None)
        flash_type = session.pop('admin_flash_type', 'success')

        conn = get_db()
        unis = conn.execute('SELECT * FROM universities ORDER BY id DESC').fetchall()
        courses = conn.execute('SELECT c.*, u.name as uname FROM courses c LEFT JOIN universities u ON c.uni_id=u.id ORDER BY c.id DESC').fetchall()
        lessons = conn.execute('SELECT l.*, c.title as cname FROM lessons l LEFT JOIN courses c ON l.course_id=c.id ORDER BY l.id DESC').fetchall()
        works = conn.execute('SELECT * FROM semester_works ORDER BY id DESC').fetchall()
        ads = conn.execute('SELECT * FROM ads_banners ORDER BY ad_type ASC, sort_order ASC, id DESC').fetchall()
        banks = conn.execute('SELECT * FROM bank_accounts ORDER BY id DESC').fetchall()
        admins_list = conn.execute('SELECT id, username, full_name, role, created_at, last_login FROM admins ORDER BY id ASC').fetchall()
        inst = conn.execute('SELECT * FROM instructors WHERE id=1').fetchone()
        settings_rows = conn.execute('SELECT key, value FROM site_settings').fetchall()
        settings = {r['key']: r['value'] for r in settings_rows}

        pending_enr = conn.execute('''
            SELECT e.id, e.user_id, e.course_id, e.status, e.created_at, u.name as uname, c.title as cname, c.price
            FROM enrollments e
            JOIN users u ON e.user_id=u.id
            JOIN courses c ON e.course_id=c.id
            WHERE e.status='pending'
            ORDER BY e.id DESC
        ''').fetchall()

        approved_enr = conn.execute('''
            SELECT e.id, e.user_id, e.course_id, e.status, e.created_at, u.name as uname, c.title as cname, c.price
            FROM enrollments e
            JOIN users u ON e.user_id=u.id
            JOIN courses c ON e.course_id=c.id
            WHERE e.status='approved'
            ORDER BY e.id DESC
        ''').fetchall()

        conn.close()

        total_revenue = sum([float(row['price'] or 0) for row in approved_enr if row['price']])
        total_students = len(set(row['user_id'] for row in approved_enr))

        uni_options = "".join([f'<option value="{u["id"]}">{html.escape(u["name"] or "")}</option>' for u in unis])
        course_options = "".join([f'<option value="{c["id"]}">{html.escape((c["uname"] or "") + " - " + (c["title"] or ""))}</option>' for c in courses])

        # شريط التنبيهات الفوري
        flash_banner = ""
        if flash_msg:
            bg_cls = "bg-emerald-50 border-emerald-300 text-emerald-800" if flash_type == "success" else "bg-rose-50 border-rose-300 text-rose-800"
            icon_str = "✅" if flash_type == "success" else "⚠️"
            flash_banner = f'''
            <div class="mb-6 p-4 rounded-2xl border {bg_cls} flex items-center justify-between shadow-xs">
                <div class="flex items-center gap-2 text-xs sm:text-sm font-black">
                    <span>{icon_str}</span>
                    <span>{html.escape(flash_msg)}</span>
                </div>
                <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-slate-700 font-black">✕</button>
            </div>'''

        # 1. بناء عناصر الطلبات المعلقة والمعتمدة
        pending_html = []
        for p in pending_enr:
            pending_html.append(f'''
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 bg-amber-50/70 rounded-2xl border border-amber-200 text-xs">
                <div>
                    <p class="font-black text-slate-900 text-sm">{html.escape(p['uname'])}</p>
                    <p class="text-slate-600 font-bold mt-0.5">المادة: {html.escape(p['cname'])} • <span class="text-emerald-700">{p['price']} ر.س</span></p>
                </div>
                <div class="flex items-center gap-2">
                    <form action="{base_url}/enrollment/status" method="POST" class="inline">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="overview">
                        <input type="hidden" name="user_id" value="{p['user_id']}">
                        <input type="hidden" name="course_id" value="{p['course_id']}">
                        <input type="hidden" name="status" value="approved">
                        <button class="bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-xl font-black transition">تفعيل الاشتراك ✅</button>
                    </form>
                    <form action="{base_url}/enrollment/delete" method="POST" class="inline" onsubmit="return confirm('حذف هذا الطلب؟')">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="overview">
                        <input type="hidden" name="user_id" value="{p['user_id']}">
                        <input type="hidden" name="course_id" value="{p['course_id']}">
                        <button class="bg-rose-100 hover:bg-rose-200 text-rose-700 px-3 py-2 rounded-xl font-black transition">حذف 🗑️</button>
                    </form>
                </div>
            </div>''')

        approved_html = []
        for a in approved_enr:
            approved_html.append(f'''
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 bg-slate-50 rounded-2xl border border-slate-200 text-xs">
                <div>
                    <span class="font-black text-slate-900">{html.escape(a['uname'])}</span>
                    <span class="text-slate-400 mx-1">•</span>
                    <span class="text-teal-700 font-bold">{html.escape(a['cname'])}</span>
                </div>
                <div class="flex items-center gap-2">
                    <form action="{base_url}/enrollment/status" method="POST" class="inline">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="overview">
                        <input type="hidden" name="user_id" value="{a['user_id']}">
                        <input type="hidden" name="course_id" value="{a['course_id']}">
                        <input type="hidden" name="status" value="pending">
                        <button class="bg-amber-100 text-amber-800 hover:bg-amber-200 px-3 py-1.5 rounded-xl font-bold">إيقاف مؤقت</button>
                    </form>
                    <form action="{base_url}/enrollment/delete" method="POST" class="inline" onsubmit="return confirm('إلغاء وحذف اشتراك الطالب؟')">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="overview">
                        <input type="hidden" name="user_id" value="{a['user_id']}">
                        <input type="hidden" name="course_id" value="{a['course_id']}">
                        <button class="bg-rose-50 text-rose-600 hover:bg-rose-100 px-3 py-1.5 rounded-xl font-bold">حذف 🗑️</button>
                    </form>
                </div>
            </div>''')

        # 2. بناء عناصر المواد والمقررات (مع نافذة التعديل لكل مادة)
        courses_html = []
        for c in courses:
            c_id = c['id']
            c_title = html.escape(c['title'] or '')
            c_code = html.escape(c['code'] or '')
            c_desc = html.escape(c['desc'] or '')
            c_fac = html.escape(c['faculty'] or 'كلية الهندسة')
            c_target = html.escape(c['target_audience'] or 'طلاب وطالبات')
            c_price = c['price'] or 0
            c_old = c['old_price'] or 0
            c_mid = c['mid_price'] or 0
            c_mid_old = c['mid_old_price'] or 0
            c_fin = c['final_price'] or 0
            c_fin_old = c['final_old_price'] or 0
            c_cover = f'<img src="/uploads/{c["cover_img"]}" class="w-14 h-14 rounded-2xl object-cover border">' if c['cover_img'] else '<div class="w-14 h-14 rounded-2xl bg-sky-100 text-sky-700 flex items-center justify-center font-black text-xl">📚</div>'

            u_opts_for_c = "".join([f'<option value="{u["id"]}" {"selected" if u["id"] == c["uni_id"] else ""}>{html.escape(u["name"] or "")}</option>' for u in unis])

            courses_html.append(f'''
            <div class="p-4 bg-slate-50 rounded-2xl border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs">
                <div class="flex items-center gap-3">
                    {c_cover}
                    <div>
                        <div class="flex items-center gap-2 flex-wrap">
                            <span class="font-black text-sm text-slate-900">{c_title}</span>
                            {f'<span class="bg-slate-200 text-slate-700 px-2 py-0.5 rounded-md text-[10px] font-bold">{c_code}</span>' if c_code else ''}
                        </div>
                        <p class="text-slate-500 font-bold mt-0.5">{html.escape(c['uname'] or 'جامعة معتمدة')} • {c_fac}</p>
                        <div class="flex items-center gap-3 mt-1 text-[11px] font-black text-teal-700">
                            <span>الكامل: {c_price} ر.س</span>
                            <span>الميد: {c_mid} ر.س</span>
                            <span>الفاينل: {c_fin} ر.س</span>
                        </div>
                    </div>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                    <a href="{site_url.rstrip('/')}/course/{c_id}" target="_blank" class="bg-slate-200 hover:bg-slate-300 text-slate-800 px-3 py-2 rounded-xl font-bold">معاينة 👁️</a>
                    <button type="button" onclick="openModal('edit-course-{c_id}')" class="bg-sky-600 hover:bg-sky-700 text-white px-3.5 py-2 rounded-xl font-black">تعديل ✏️</button>
                    <form action="{base_url}/course/delete/{c_id}" method="POST" class="inline" onsubmit="return confirm('حذف هذه المادة وجميع محاضراتها نهائياً؟')">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="courses">
                        <button class="bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 px-3.5 py-2 rounded-xl font-black">حذف 🗑️</button>
                    </form>
                </div>
            </div>

            <!-- نافذة تعديل المادة -->
            <div id="edit-course-{c_id}" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs hidden p-4 overflow-y-auto">
                <div class="bg-white rounded-3xl max-w-xl w-full p-6 shadow-2xl border border-slate-200 my-8">
                    <div class="flex items-center justify-between pb-3 mb-4 border-b border-slate-100">
                        <h4 class="font-black text-base text-slate-900">✏️ تعديل المادة: {c_title}</h4>
                        <button type="button" onclick="closeModal('edit-course-{c_id}')" class="text-slate-400 hover:text-slate-700 font-black text-lg">✕</button>
                    </div>
                    <form action="{base_url}/course/edit/{c_id}" method="POST" enctype="multipart/form-data" class="space-y-3 text-xs">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="courses">
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">الجامعة:</label>
                                <select name="uni_id" class="w-full p-2.5 border rounded-xl font-bold bg-white">{u_opts_for_c}</select>
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">اسم المادة:</label>
                                <input type="text" name="title" value="{c_title}" required class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                        </div>
                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">رمز المقرر:</label>
                                <input type="text" name="code" value="{c_code}" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">الكلية:</label>
                                <input type="text" name="faculty" value="{c_fac}" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">الفئة المستهدفة:</label>
                                <input type="text" name="target_audience" value="{c_target}" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                        </div>
                        <div class="grid grid-cols-2 sm:grid-cols-3 gap-3 bg-slate-50 p-3 rounded-2xl border">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">سعر المنهج كامل:</label>
                                <input type="number" step="0.5" name="price" value="{c_price}" required class="w-full p-2 border rounded-xl font-bold bg-white">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-500 font-bold">السعر السابق (كامل):</label>
                                <input type="number" step="0.5" name="old_price" value="{c_old}" class="w-full p-2 border rounded-xl font-bold bg-white">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">سعر باقة الميد:</label>
                                <input type="number" step="0.5" name="mid_price" value="{c_mid}" class="w-full p-2 border rounded-xl font-bold bg-white">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-500 font-bold">السعر السابق (ميد):</label>
                                <input type="number" step="0.5" name="mid_old_price" value="{c_mid_old}" class="w-full p-2 border rounded-xl font-bold bg-white">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">سعر باقة الفاينل:</label>
                                <input type="number" step="0.5" name="final_price" value="{c_fin}" class="w-full p-2 border rounded-xl font-bold bg-white">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-500 font-bold">السعر السابق (فاينل):</label>
                                <input type="number" step="0.5" name="final_old_price" value="{c_fin_old}" class="w-full p-2 border rounded-xl font-bold bg-white">
                            </div>
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">تحديث صورة الغلاف (اختياري):</label>
                            <input type="file" name="cover_file" accept="image/*" class="w-full p-2 border border-dashed rounded-xl bg-slate-50">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">وصف وتفاصيل المادة:</label>
                            <textarea name="desc" rows="3" required class="w-full p-2.5 border rounded-xl font-medium">{c_desc}</textarea>
                        </div>
                        <div class="flex justify-end gap-2 pt-2">
                            <button type="button" onclick="closeModal('edit-course-{c_id}')" class="px-4 py-2.5 rounded-xl bg-slate-100 text-slate-700 font-bold">إلغاء</button>
                            <button type="submit" class="px-6 py-2.5 rounded-xl bg-sky-600 hover:bg-sky-700 text-white font-black">حفظ التعديلات 💾</button>
                        </div>
                    </form>
                </div>
            </div>''')

        # 3. بناء عناصر المحاضرات والملخصات (مع نافذة التعديل لكل درس)
        lessons_html = []
        for l in lessons:
            l_id = l['id']
            l_title = html.escape(l['title'] or '')
            l_cname = html.escape(l['cname'] or 'مقرر غير محدد')
            has_vid = bool(l['video_filename'])
            has_pdf = bool(l['pdf_filename'])
            c_opts_for_l = "".join([f'<option value="{c["id"]}" {"selected" if c["id"] == l["course_id"] else ""}>{html.escape((c["uname"] or "") + " - " + (c["title"] or ""))}</option>' for c in courses])

            lessons_html.append(f'''
            <div class="p-4 bg-slate-50 rounded-2xl border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                <div>
                    <div class="flex items-center gap-2">
                        <span class="font-black text-sm text-slate-900">{l_title}</span>
                        <span class="bg-sky-100 text-sky-800 px-2.5 py-0.5 rounded-full text-[11px] font-bold">{l_cname}</span>
                    </div>
                    <div class="flex items-center gap-3 mt-1.5 text-[11px] font-bold">
                        <span class="{'text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-md' if has_vid else 'text-slate-400'}">{'🎬 فيديو مرفوع' if has_vid else 'بدون فيديو'}</span>
                        <span class="{'text-blue-700 bg-blue-50 px-2 py-0.5 rounded-md' if has_pdf else 'text-slate-400'}">{'📄 ملخص PDF مرفوع' if has_pdf else 'بدون ملخص PDF'}</span>
                    </div>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                    <button type="button" onclick="openModal('edit-lesson-{l_id}')" class="bg-sky-600 hover:bg-sky-700 text-white px-3.5 py-2 rounded-xl font-black">تعديل ✏️</button>
                    <form action="{base_url}/lesson/delete/{l_id}" method="POST" class="inline" onsubmit="return confirm('حذف هذه المحاضرة وملفاتها؟')">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="lessons">
                        <button class="bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 px-3.5 py-2 rounded-xl font-black">حذف 🗑️</button>
                    </form>
                </div>
            </div>

            <!-- نافذة تعديل المحاضرة -->
            <div id="edit-lesson-{l_id}" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs hidden p-4">
                <div class="bg-white rounded-3xl max-w-lg w-full p-6 shadow-2xl border border-slate-200">
                    <div class="flex items-center justify-between pb-3 mb-4 border-b border-slate-100">
                        <h4 class="font-black text-base text-slate-900">✏️ تعديل المحاضرة: {l_title}</h4>
                        <button type="button" onclick="closeModal('edit-lesson-{l_id}')" class="text-slate-400 hover:text-slate-700 font-black text-lg">✕</button>
                    </div>
                    <form action="{base_url}/lesson/edit/{l_id}" method="POST" enctype="multipart/form-data" class="space-y-3 text-xs">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="lessons">
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">المادة التابع لها:</label>
                            <select name="course_id" class="w-full p-2.5 border rounded-xl font-bold bg-white">{c_opts_for_l}</select>
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">عنوان المحاضرة:</label>
                            <input type="text" name="title" value="{l_title}" required class="w-full p-2.5 border rounded-xl font-bold">
                        </div>
                        <div class="bg-slate-50 p-3 rounded-2xl border space-y-2.5">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">استبدال ملف الفيديو (اختياري):</label>
                                <input type="file" name="video_file" accept="video/*" class="w-full p-2 border border-dashed rounded-xl bg-white">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">استبدال ملف الملخص PDF (اختياري):</label>
                                <input type="file" name="pdf_file" accept=".pdf" class="w-full p-2 border border-dashed rounded-xl bg-white">
                            </div>
                        </div>
                        <div class="flex justify-end gap-2 pt-2">
                            <button type="button" onclick="closeModal('edit-lesson-{l_id}')" class="px-4 py-2.5 rounded-xl bg-slate-100 text-slate-700 font-bold">إلغاء</button>
                            <button type="submit" class="px-6 py-2.5 rounded-xl bg-sky-600 hover:bg-sky-700 text-white font-black">حفظ التعديلات 💾</button>
                        </div>
                    </form>
                </div>
            </div>''')

        # 4. بناء عناصر الأعمال الفصلية والمشاريع (مع نافذة التعديل)
        works_html = []
        for w in works:
            w_id = w['id']
            w_title = html.escape(w['title'] or '')
            w_fac = html.escape(w['faculty'] or '')
            w_desc = html.escape(w['desc'] or '')
            w_cov_raw = w['cover_img'] or ''
            if w_cov_raw:
                w_img_src = w_cov_raw if w_cov_raw.startswith('http') else f'/uploads/{w_cov_raw}'
                w_thumb = f'<img src="{html.escape(w_img_src)}" class="w-14 h-14 rounded-2xl object-cover border">'
            else:
                w_thumb = '<div class="w-14 h-14 rounded-2xl bg-teal-100 text-teal-700 flex items-center justify-center text-xl font-black">📝</div>'

            works_html.append(f'''
            <div class="p-4 bg-slate-50 rounded-2xl border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs">
                <div class="flex items-center gap-3">
                    {w_thumb}
                    <div>
                        <p class="font-black text-sm text-slate-900">{w_title}</p>
                        <p class="text-amber-800 bg-amber-100 px-2.5 py-0.5 rounded-full inline-block text-[10px] font-black mt-0.5">{w_fac}</p>
                        <p class="text-slate-500 mt-1 line-clamp-1">{w_desc}</p>
                    </div>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                    <button type="button" onclick="openModal('edit-work-{w_id}')" class="bg-sky-600 hover:bg-sky-700 text-white px-3.5 py-2 rounded-xl font-black">تعديل ✏️</button>
                    <form action="{base_url}/work/delete/{w_id}" method="POST" class="inline" onsubmit="return confirm('حذف هذا العمل الفصلي؟')">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="works">
                        <button class="bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 px-3.5 py-2 rounded-xl font-black">حذف 🗑️</button>
                    </form>
                </div>
            </div>

            <!-- نافذة تعديل العمل الفصلي -->
            <div id="edit-work-{w_id}" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs hidden p-4">
                <div class="bg-white rounded-3xl max-w-lg w-full p-6 shadow-2xl border border-slate-200">
                    <div class="flex items-center justify-between pb-3 mb-4 border-b border-slate-100">
                        <h4 class="font-black text-base text-slate-900">✏️ تعديل العمل الفصلي</h4>
                        <button type="button" onclick="closeModal('edit-work-{w_id}')" class="text-slate-400 hover:text-slate-700 font-black text-lg">✕</button>
                    </div>
                    <form action="{base_url}/work/edit/{w_id}" method="POST" enctype="multipart/form-data" class="space-y-3 text-xs">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="works">
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">عنوان العمل أو المشروع:</label>
                            <input type="text" name="title" value="{w_title}" required class="w-full p-2.5 border rounded-xl font-bold">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">الكلية أو التخصص:</label>
                            <input type="text" name="faculty" value="{w_fac}" required class="w-full p-2.5 border rounded-xl font-bold">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">الوصف والتفاصيل:</label>
                            <textarea name="desc" rows="3" required class="w-full p-2.5 border rounded-xl font-medium">{w_desc}</textarea>
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">رفع صورة غلاف جديدة (أو اتركه فارغاً للإبقاء على الحالية):</label>
                            <input type="file" name="cover_img" accept="image/*" class="w-full p-2 border border-dashed rounded-xl bg-slate-50">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">أو رابط صورة خارجي:</label>
                            <input type="text" name="cover_url" value="{html.escape(w_cov_raw if w_cov_raw.startswith('http') else '')}" placeholder="https://..." class="w-full p-2.5 border rounded-xl font-mono text-[11px]">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">رفع ملف مرفق جديد (PDF / ZIP - اختياري):</label>
                            <input type="file" name="work_file" class="w-full p-2 border border-dashed rounded-xl bg-slate-50">
                        </div>
                        <div class="flex justify-end gap-2 pt-2">
                            <button type="button" onclick="closeModal('edit-work-{w_id}')" class="px-4 py-2.5 rounded-xl bg-slate-100 text-slate-700 font-bold">إلغاء</button>
                            <button type="submit" class="px-6 py-2.5 rounded-xl bg-sky-600 hover:bg-sky-700 text-white font-black">حفظ التعديلات 💾</button>
                        </div>
                    </form>
                </div>
            </div>''')

        # 5. بناء عناصر الإعلانات والصور والسلايدر (مع نافذة التعديل)
        ads_html = []
        type_labels = {
            'slider': ('🖼️ سلايدر الصور الرئيسي', 'bg-indigo-100 text-indigo-800'),
            'banner': ('📢 بنر إعلاني مصور', 'bg-teal-100 text-teal-800'),
            'ticker': ('⚡ شريط إعلاني متحرك', 'bg-amber-100 text-amber-900')
        }
        for ad in ads:
            ad_id = ad['id']
            ad_title = html.escape(ad['title'] or '')
            ad_sub = html.escape(ad['subtitle'] or '')
            ad_badge = html.escape(ad['badge'] or '')
            ad_link = html.escape(ad['link_url'] or '')
            ad_type = ad['ad_type'] or 'slider'
            ad_active = int(ad['is_active'] or 0)
            ad_order = int(ad['sort_order'] or 0)
            ad_img_raw = ad['image_url'] or ''
            t_label, t_cls = type_labels.get(ad_type, ('إعلان', 'bg-slate-100 text-slate-700'))

            if ad_img_raw:
                img_src = ad_img_raw if ad_img_raw.startswith('http') else f'/uploads/{ad_img_raw}'
                ad_thumb = f'<img src="{html.escape(img_src)}" class="w-16 h-12 rounded-xl object-cover border">'
            else:
                ad_thumb = '<div class="w-16 h-12 rounded-xl bg-amber-100 text-amber-700 flex items-center justify-center text-lg font-black">📢</div>'

            ads_html.append(f'''
            <div class="p-4 bg-slate-50 rounded-2xl border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs">
                <div class="flex items-center gap-3">
                    {ad_thumb}
                    <div>
                        <div class="flex items-center gap-2 flex-wrap">
                            <span class="px-2.5 py-0.5 rounded-full text-[10px] font-black {t_cls}">{t_label}</span>
                            <span class="px-2 py-0.5 rounded-full text-[10px] font-black {'bg-emerald-100 text-emerald-800' if ad_active else 'bg-rose-100 text-rose-700'}">{'نشط ✅' if ad_active else 'مخفي ⏸️'}</span>
                            {f'<span class="bg-slate-200 text-slate-800 px-2 py-0.5 rounded-md text-[10px] font-bold">{ad_badge}</span>' if ad_badge else ''}
                        </div>
                        <p class="font-black text-sm text-slate-900 mt-1">{ad_title}</p>
                        {f'<p class="text-slate-500 font-medium mt-0.5">{ad_sub}</p>' if ad_sub else ''}
                    </div>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                    <button type="button" onclick="openModal('edit-ad-{ad_id}')" class="bg-sky-600 hover:bg-sky-700 text-white px-3.5 py-2 rounded-xl font-black">تعديل ✏️</button>
                    <form action="{base_url}/ad/delete/{ad_id}" method="POST" class="inline" onsubmit="return confirm('حذف هذا الإعلان/الصورة؟')">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="ads">
                        <button class="bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 px-3.5 py-2 rounded-xl font-black">حذف 🗑️</button>
                    </form>
                </div>
            </div>

            <!-- نافذة تعديل الإعلان / الصورة -->
            <div id="edit-ad-{ad_id}" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs hidden p-4">
                <div class="bg-white rounded-3xl max-w-lg w-full p-6 shadow-2xl border border-slate-200">
                    <div class="flex items-center justify-between pb-3 mb-4 border-b border-slate-100">
                        <h4 class="font-black text-base text-slate-900">✏️ تعديل الإعلان / الصورة</h4>
                        <button type="button" onclick="closeModal('edit-ad-{ad_id}')" class="text-slate-400 hover:text-slate-700 font-black text-lg">✕</button>
                    </div>
                    <form action="{base_url}/ad/edit/{ad_id}" method="POST" enctype="multipart/form-data" class="space-y-3 text-xs">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="ads">
                        <div class="grid grid-cols-2 gap-3">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">مكان ونوع الإعلان:</label>
                                <select name="ad_type" class="w-full p-2.5 border rounded-xl font-bold bg-white">
                                    <option value="slider" {"selected" if ad_type == "slider" else ""}>سلايدر الصور الرئيسي</option>
                                    <option value="banner" {"selected" if ad_type == "banner" else ""}>بنر إعلاني مصور</option>
                                    <option value="ticker" {"selected" if ad_type == "ticker" else ""}>شريط إعلاني متحرك علوي</option>
                                </select>
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">الحالة:</label>
                                <select name="is_active" class="w-full p-2.5 border rounded-xl font-bold bg-white">
                                    <option value="1" {"selected" if ad_active == 1 else ""}>نشط (معروض بالموقع)</option>
                                    <option value="0" {"selected" if ad_active == 0 else ""}>مخفي</option>
                                </select>
                            </div>
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">العنوان الرئيسي / النص الإعلاني:</label>
                            <input type="text" name="title" value="{ad_title}" required class="w-full p-2.5 border rounded-xl font-bold">
                        </div>
                        <div class="grid grid-cols-2 gap-3">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">شارة صغيرة (Badge):</label>
                                <input type="text" name="badge" value="{ad_badge}" placeholder="مثال: 💻 برمجة وتطوير" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">الترتيب:</label>
                                <input type="number" name="sort_order" value="{ad_order}" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">وصف فرعي (للسلايدر والبنرات):</label>
                            <input type="text" name="subtitle" value="{ad_sub}" class="w-full p-2.5 border rounded-xl font-medium">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">رفع صورة جديدة (من جهازك):</label>
                            <input type="file" name="image_file" accept="image/*" class="w-full p-2 border border-dashed rounded-xl bg-slate-50">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">أو رابط الصورة (URL):</label>
                            <input type="text" name="image_url" value="{html.escape(ad_img_raw if ad_img_raw.startswith('http') else '')}" placeholder="https://..." class="w-full p-2.5 border rounded-xl font-mono text-[11px]">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">رابط عند الضغط على البنر (اختياري):</label>
                            <input type="text" name="link_url" value="{ad_link}" placeholder="https://wa.me/..." class="w-full p-2.5 border rounded-xl font-mono text-[11px]">
                        </div>
                        <div class="flex justify-end gap-2 pt-2">
                            <button type="button" onclick="closeModal('edit-ad-{ad_id}')" class="px-4 py-2.5 rounded-xl bg-slate-100 text-slate-700 font-bold">إلغاء</button>
                            <button type="submit" class="px-6 py-2.5 rounded-xl bg-sky-600 hover:bg-sky-700 text-white font-black">حفظ التعديلات 💾</button>
                        </div>
                    </form>
                </div>
            </div>''')

        # 6. بناء عناصر الجامعات (مع نافذة التعديل)
        unis_html = []
        for u in unis:
            u_id = u['id']
            u_name = html.escape(u['name'] or '')
            u_desc = html.escape(u['desc'] or '')
            u_emoji = html.escape(u['logo'] or '🏛️')
            u_logo_img = u['logo_img'] if 'logo_img' in u.keys() else None
            u_badge = f'<img src="/uploads/{u_logo_img}" class="w-12 h-12 rounded-2xl object-contain bg-white p-1 border">' if u_logo_img else f'<div class="w-12 h-12 rounded-2xl bg-slate-200 flex items-center justify-center text-2xl">{u_emoji}</div>'

            unis_html.append(f'''
            <div class="p-4 bg-slate-50 rounded-2xl border border-slate-200 flex items-center justify-between gap-3 text-xs">
                <div class="flex items-center gap-3">
                    {u_badge}
                    <div>
                        <p class="font-black text-sm text-slate-900">{u_name}</p>
                        <p class="text-slate-500 font-medium">{u_desc}</p>
                    </div>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                    <button type="button" onclick="openModal('edit-uni-{u_id}')" class="bg-sky-600 hover:bg-sky-700 text-white px-3.5 py-2 rounded-xl font-black">تعديل ✏️</button>
                    <form action="{base_url}/uni/delete/{u_id}" method="POST" class="inline" onsubmit="return confirm('حذف الجامعة وجميع المواد التابعة لها؟')">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="unis">
                        <button class="bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 px-3.5 py-2 rounded-xl font-black">حذف 🗑️</button>
                    </form>
                </div>
            </div>

            <!-- نافذة تعديل الجامعة -->
            <div id="edit-uni-{u_id}" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs hidden p-4">
                <div class="bg-white rounded-3xl max-w-md w-full p-6 shadow-2xl border border-slate-200">
                    <div class="flex items-center justify-between pb-3 mb-4 border-b border-slate-100">
                        <h4 class="font-black text-base text-slate-900">✏️ تعديل الجامعة</h4>
                        <button type="button" onclick="closeModal('edit-uni-{u_id}')" class="text-slate-400 hover:text-slate-700 font-black text-lg">✕</button>
                    </div>
                    <form action="{base_url}/uni/edit/{u_id}" method="POST" enctype="multipart/form-data" class="space-y-3 text-xs">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="unis">
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">اسم الجامعة:</label>
                            <input type="text" name="name" value="{u_name}" required class="w-full p-2.5 border rounded-xl font-bold">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">وصف الجامعة:</label>
                            <input type="text" name="desc" value="{u_desc}" class="w-full p-2.5 border rounded-xl font-medium">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">الرمز التعبيري (في حال عدم وجود صورة شعار):</label>
                            <input type="text" name="logo" value="{u_emoji}" class="w-full p-2.5 border rounded-xl font-bold">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">تحديث شعار الجامعة (صورة):</label>
                            <input type="file" name="logo_file" accept="image/*" class="w-full p-2 border border-dashed rounded-xl bg-slate-50">
                        </div>
                        <div class="flex justify-end gap-2 pt-2">
                            <button type="button" onclick="closeModal('edit-uni-{u_id}')" class="px-4 py-2.5 rounded-xl bg-slate-100 text-slate-700 font-bold">إلغاء</button>
                            <button type="submit" class="px-6 py-2.5 rounded-xl bg-sky-600 hover:bg-sky-700 text-white font-black">حفظ التعديلات 💾</button>
                        </div>
                    </form>
                </div>
            </div>''')

        # 7. بناء عناصر الحسابات البنكية (مع نافذة التعديل)
        banks_html = []
        for b in banks:
            b_id = b['id']
            b_name = html.escape(b['bank_name'] or '')
            b_ben = html.escape(b['beneficiary'] or '')
            b_acc = html.escape(b['account_num'] or '')
            b_iban = html.escape(b['iban'] or '')

            banks_html.append(f'''
            <div class="p-4 bg-slate-50 rounded-2xl border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                <div>
                    <p class="font-black text-sm text-slate-900">{b_name} — <span class="text-teal-700">{b_ben}</span></p>
                    <p class="font-mono text-slate-600 font-bold mt-0.5">الحساب: {b_acc} {f" | IBAN: {b_iban}" if b_iban else ""}</p>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                    <button type="button" onclick="openModal('edit-bank-{b_id}')" class="bg-sky-600 hover:bg-sky-700 text-white px-3.5 py-2 rounded-xl font-black">تعديل ✏️</button>
                    <form action="{base_url}/bank/delete/{b_id}" method="POST" class="inline" onsubmit="return confirm('حذف هذا الحساب البنكي؟')">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="info">
                        <button class="bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 px-3.5 py-2 rounded-xl font-black">حذف 🗑️</button>
                    </form>
                </div>
            </div>

            <!-- نافذة تعديل الحساب البنكي -->
            <div id="edit-bank-{b_id}" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs hidden p-4">
                <div class="bg-white rounded-3xl max-w-md w-full p-6 shadow-2xl border border-slate-200">
                    <div class="flex items-center justify-between pb-3 mb-4 border-b border-slate-100">
                        <h4 class="font-black text-base text-slate-900">✏️ تعديل الحساب البنكي</h4>
                        <button type="button" onclick="closeModal('edit-bank-{b_id}')" class="text-slate-400 hover:text-slate-700 font-black text-lg">✕</button>
                    </div>
                    <form action="{base_url}/bank/edit/{b_id}" method="POST" class="space-y-3 text-xs">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="info">
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">اسم البنك أو المحفظة:</label>
                            <input type="text" name="bank_name" value="{b_name}" required class="w-full p-2.5 border rounded-xl font-bold">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">اسم المستفيد:</label>
                            <input type="text" name="beneficiary" value="{b_ben}" required class="w-full p-2.5 border rounded-xl font-bold">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">رقم الحساب:</label>
                            <input type="text" name="account_num" value="{b_acc}" required class="w-full p-2.5 border rounded-xl font-mono font-bold">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">رقم الآيبان (IBAN):</label>
                            <input type="text" name="iban" value="{b_iban}" class="w-full p-2.5 border rounded-xl font-mono font-bold">
                        </div>
                        <div class="flex justify-end gap-2 pt-2">
                            <button type="button" onclick="closeModal('edit-bank-{b_id}')" class="px-4 py-2.5 rounded-xl bg-slate-100 text-slate-700 font-bold">إلغاء</button>
                            <button type="submit" class="px-6 py-2.5 rounded-xl bg-sky-600 hover:bg-sky-700 text-white font-black">حفظ التعديلات 💾</button>
                        </div>
                    </form>
                </div>
            </div>''')

        # 8. بناء قائمة حسابات الأدمن (مع التعديل والحذف)
        admins_html = []
        current_admin_id = session.get('admin_id')
        for adm in admins_list:
            a_id = adm['id']
            a_user = html.escape(adm['username'] or '')
            a_name = html.escape(adm['full_name'] or '')
            a_role = html.escape(adm['role'] or 'مدير عام')
            is_self = (a_id == current_admin_id)

            del_btn = f'''
            <form action="{base_url}/admins/delete/{a_id}" method="POST" class="inline" onsubmit="return confirm('هل أنت متأكد من حذف حساب الأدمن ({a_user})؟')">
                <input type="hidden" name="csrf_token" value="{csrf}">
                <input type="hidden" name="return_tab" value="admins">
                <button class="bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 px-3 py-2 rounded-xl font-black">حذف 🗑️</button>
            </form>''' if not is_self and len(admins_list) > 1 else '<span class="text-[11px] bg-emerald-50 text-emerald-700 px-3 py-1.5 rounded-xl font-black border border-emerald-200">حسابك الحالي 👤</span>'

            admins_html.append(f'''
            <div class="p-4 bg-slate-50 rounded-2xl border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-2xl bg-slate-900 text-white flex items-center justify-center font-black text-sm">🛡️</div>
                    <div>
                        <div class="flex items-center gap-2">
                            <span class="font-black text-sm text-slate-900">{a_name}</span>
                            <span class="bg-sky-100 text-sky-800 px-2 py-0.5 rounded-md font-mono font-bold text-[11px]">@{a_user}</span>
                            <span class="bg-purple-100 text-purple-800 px-2 py-0.5 rounded-full text-[10px] font-black">{a_role}</span>
                        </div>
                        <p class="text-[11px] text-slate-400 font-bold mt-0.5">آخر دخول: {adm['last_login'] or 'الآن'}</p>
                    </div>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                    <button type="button" onclick="openModal('edit-admin-{a_id}')" class="bg-sky-600 hover:bg-sky-700 text-white px-3.5 py-2 rounded-xl font-black">تعديل البيانات / الرمز ✏️</button>
                    {del_btn}
                </div>
            </div>

            <!-- نافذة تعديل بيانات الأدمن -->
            <div id="edit-admin-{a_id}" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs hidden p-4">
                <div class="bg-white rounded-3xl max-w-md w-full p-6 shadow-2xl border border-slate-200">
                    <div class="flex items-center justify-between pb-3 mb-4 border-b border-slate-100">
                        <h4 class="font-black text-base text-slate-900">✏️ تعديل حساب الأدمن (@{a_user})</h4>
                        <button type="button" onclick="closeModal('edit-admin-{a_id}')" class="text-slate-400 hover:text-slate-700 font-black text-lg">✕</button>
                    </div>
                    <form action="{base_url}/admins/edit/{a_id}" method="POST" class="space-y-3 text-xs">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="admins">
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">اسم المستخدم (لتسجيل الدخول):</label>
                            <input type="text" name="username" value="{a_user}" required class="w-full p-2.5 border rounded-xl font-bold">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">الاسم الكامل / المسمى:</label>
                            <input type="text" name="full_name" value="{a_name}" required class="w-full p-2.5 border rounded-xl font-bold">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">الصلاحية / الدور:</label>
                            <select name="role" class="w-full p-2.5 border rounded-xl font-bold bg-white">
                                <option value="مدير عام" {"selected" if a_role == "مدير عام" else ""}>مدير عام (كامل الصلاحيات)</option>
                                <option value="مشرف محتوى" {"selected" if a_role == "مشرف محتوى" else ""}>مشرف محتوى</option>
                                <option value="محرر" {"selected" if a_role == "محرر" else ""}>محرر</option>
                            </select>
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">كلمة مرور جديدة (اتركها فارغة إذا لا تريد تغييرها):</label>
                            <input type="password" name="new_password" placeholder="أدخل كلمة مرور جديدة فقط عند الرغبة بالتغيير" class="w-full p-2.5 border rounded-xl font-bold">
                        </div>
                        <div class="flex justify-end gap-2 pt-2">
                            <button type="button" onclick="closeModal('edit-admin-{a_id}')" class="px-4 py-2.5 rounded-xl bg-slate-100 text-slate-700 font-bold">إلغاء</button>
                            <button type="submit" class="px-6 py-2.5 rounded-xl bg-sky-600 hover:bg-sky-700 text-white font-black">حفظ التعديلات 💾</button>
                        </div>
                    </form>
                </div>
            </div>''')

        # تجهيز المقررات لنظرة عامة
        overview_courses_list = []
        for c in courses:
            overview_courses_list.append(f'''
            <div class="p-3.5 bg-slate-50 rounded-2xl border border-slate-200 flex items-center justify-between gap-2 text-xs">
                <div>
                    <p class="font-black text-slate-900">{html.escape(c["title"] or "")}</p>
                    <p class="text-slate-500 font-bold">{html.escape(c["uname"] or "")} • {c["price"]:g} ر.س</p>
                </div>
                <div class="flex items-center gap-1.5 shrink-0">
                    <button type="button" onclick="openAdminTab('courses'); openModal('edit-course-{c["id"]}')" class="bg-sky-600 hover:bg-sky-700 text-white px-3 py-1.5 rounded-xl font-black">تعديل ✏️</button>
                    <form action="{base_url}/course/delete/{c["id"]}" method="POST" class="inline" onsubmit="return confirm('حذف هذه المادة نهائياً؟')">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="overview">
                        <button class="bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 px-3 py-1.5 rounded-xl font-black">حذف 🗑️</button>
                    </form>
                </div>
            </div>''')
        overview_courses_html = "".join(overview_courses_list) or '<p class="text-xs text-slate-400 text-center py-6">لا توجد مقررات حالياً</p>'

        # تجهيز الأعمال لنظرة عامة
        overview_works_list = []
        for w in works:
            overview_works_list.append(f'''
            <div class="p-3.5 bg-slate-50 rounded-2xl border border-slate-200 flex items-center justify-between gap-2 text-xs">
                <div>
                    <p class="font-black text-slate-900">{html.escape(w["title"] or "")}</p>
                    <p class="text-teal-700 font-bold">{html.escape(w["faculty"] or "")}</p>
                </div>
                <div class="flex items-center gap-1.5 shrink-0">
                    <button type="button" onclick="openAdminTab('works'); openModal('edit-work-{w["id"]}')" class="bg-sky-600 hover:bg-sky-700 text-white px-3 py-1.5 rounded-xl font-black">تعديل ✏️</button>
                    <form action="{base_url}/work/delete/{w["id"]}" method="POST" class="inline" onsubmit="return confirm('حذف هذا العمل الفصلي نهائياً؟')">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="overview">
                        <button class="bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 px-3 py-1.5 rounded-xl font-black">حذف 🗑️</button>
                    </form>
                </div>
            </div>''')
        overview_works_html = "".join(overview_works_list) or '<p class="text-xs text-slate-400 text-center py-6">لا توجد أعمال فصلية حالياً</p>'

        content = f'''
        {flash_banner}

        <!-- ==================== 1. تبويب نظرة عامة والطلبات ==================== -->
        <div id="tab-overview" class="tab-panel active space-y-6">
            <!-- بطاقات الإحصائيات -->
            <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
                <div class="bg-white p-4 rounded-3xl border border-slate-200 shadow-xs">
                    <span class="text-[11px] font-bold text-slate-400 block">إجمالي المبيعات</span>
                    <span class="text-xl font-black text-emerald-600 mt-1 block">{total_revenue:g} <span class="text-xs">ر.س</span></span>
                </div>
                <div class="bg-white p-4 rounded-3xl border border-slate-200 shadow-xs">
                    <span class="text-[11px] font-bold text-slate-400 block">الطلاب المشتركون</span>
                    <span class="text-xl font-black text-slate-900 mt-1 block">{total_students}</span>
                </div>
                <div class="bg-white p-4 rounded-3xl border border-slate-200 shadow-xs">
                    <span class="text-[11px] font-bold text-slate-400 block">طلبات بانتظار التفعيل</span>
                    <span class="text-xl font-black text-amber-600 mt-1 block">{len(pending_enr)}</span>
                </div>
                <div class="bg-white p-4 rounded-3xl border border-slate-200 shadow-xs">
                    <span class="text-[11px] font-bold text-slate-400 block">المواد والمقررات</span>
                    <span class="text-xl font-black text-sky-600 mt-1 block">{len(courses)}</span>
                </div>
                <div class="bg-white p-4 rounded-3xl border border-slate-200 shadow-xs">
                    <span class="text-[11px] font-bold text-slate-400 block">الأعمال والمشاريع</span>
                    <span class="text-xl font-black text-teal-600 mt-1 block">{len(works)}</span>
                </div>
                <div class="bg-white p-4 rounded-3xl border border-slate-200 shadow-xs">
                    <span class="text-[11px] font-bold text-slate-400 block">الإعلانات والصور</span>
                    <span class="text-xl font-black text-indigo-600 mt-1 block">{len(ads)}</span>
                </div>
            </div>

            <!-- أزرار الوصول السريع -->
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <button onclick="openAdminTab('courses')" class="p-4 bg-white hover:bg-sky-50 border border-slate-200 rounded-2xl text-right transition flex items-center justify-between">
                    <div>
                        <span class="text-lg block">📚</span>
                        <span class="font-black text-xs text-slate-900">إضافة وتعديل المواد</span>
                    </div>
                    <span class="text-slate-400">&lsaquo;</span>
                </button>
                <button onclick="openAdminTab('works')" class="p-4 bg-white hover:bg-teal-50 border border-slate-200 rounded-2xl text-right transition flex items-center justify-between">
                    <div>
                        <span class="text-lg block">📝</span>
                        <span class="font-black text-xs text-slate-900">رفع الأعمال والمشاريع</span>
                    </div>
                    <span class="text-slate-400">&lsaquo;</span>
                </button>
                <button onclick="openAdminTab('ads')" class="p-4 bg-white hover:bg-amber-50 border border-slate-200 rounded-2xl text-right transition flex items-center justify-between">
                    <div>
                        <span class="text-lg block">📢</span>
                        <span class="font-black text-xs text-slate-900">الإعلانات وصور السلايدر</span>
                    </div>
                    <span class="text-slate-400">&lsaquo;</span>
                </button>
                <button onclick="openAdminTab('admins')" class="p-4 bg-white hover:bg-purple-50 border border-slate-200 rounded-2xl text-right transition flex items-center justify-between">
                    <div>
                        <span class="text-lg block">🛡️</span>
                        <span class="font-black text-xs text-slate-900">إدارة الأدمن وكلمة السر</span>
                    </div>
                    <span class="text-slate-400">&lsaquo;</span>
                </button>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <!-- طلبات التفعيل المعلقة -->
                <div class="bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                    <h3 class="font-black text-base text-slate-900 mb-4 flex items-center justify-between">
                        <span>🔔 طلبات الاشتراك المعلقة ({len(pending_enr)})</span>
                    </h3>
                    <div class="space-y-3 max-h-96 overflow-y-auto">
                        {''.join(pending_html) if pending_html else '<p class="text-xs text-slate-400 text-center py-8 bg-slate-50 rounded-2xl">لا توجد طلبات معلقة حالياً</p>'}
                    </div>
                </div>

                <!-- تفعيل يدوي لطالب + الاشتراكات النشطة -->
                <div class="bg-white p-6 rounded-3xl border border-slate-200 shadow-xs space-y-5">
                    <div>
                        <h3 class="font-black text-base text-slate-900 mb-3">➕ تفعيل مقرر لطالب يدوياً</h3>
                        <form action="{base_url}/enrollment/add-manual" method="POST" class="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                            <input type="hidden" name="csrf_token" value="{csrf}">
                            <input type="hidden" name="return_tab" value="overview">
                            <input type="text" name="student_name" placeholder="اسم الطالب الثلاثي" required class="p-2.5 border rounded-xl font-bold">
                            <select name="course_id" class="p-2.5 border rounded-xl font-bold bg-white">{course_options}</select>
                            <button class="bg-slate-900 hover:bg-slate-800 text-white font-black rounded-xl py-2.5 px-4">تفعيل فوري ✅</button>
                        </form>
                    </div>
                    <div class="border-t border-slate-100 pt-4">
                        <h4 class="font-black text-xs text-slate-700 mb-3">الاشتراكات المفعلة حالياً ({len(approved_enr)}):</h4>
                        <div class="space-y-2 max-h-60 overflow-y-auto">
                            {''.join(approved_html) if approved_html else '<p class="text-xs text-slate-400 text-center py-4">لا توجد اشتراكات مفعلة بعد</p>'}
                        </div>
                    </div>
                </div>
            </div>

            <!-- التحكم السريع بالمقررات والملخصات والأعمال والمشاريع المميزة (إضافة / تعديل / حذف) -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div class="bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="font-black text-base text-slate-900">📚 المقررات والملخصات الحالية ({len(courses)})</h3>
                        <button type="button" onclick="openAdminTab('courses')" class="bg-sky-600 hover:bg-sky-700 text-white text-xs font-black px-4 py-2 rounded-xl transition">➕ إضافة / إدارة المقررات</button>
                    </div>
                    <div class="space-y-2.5 max-h-96 overflow-y-auto">
                        {overview_courses_html}
                    </div>
                </div>

                <div class="bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="font-black text-base text-slate-900">📝 الأعمال والمشاريع الاحترافية ({len(works)})</h3>
                        <button type="button" onclick="openAdminTab('works')" class="bg-teal-600 hover:bg-teal-700 text-white text-xs font-black px-4 py-2 rounded-xl transition">➕ إضافة / إدارة الأعمال</button>
                    </div>
                    <div class="space-y-2.5 max-h-96 overflow-y-auto">
                        {overview_works_html}
                    </div>
                </div>
            </div>
        </div>

        <!-- ==================== 2. تبويب إدارة المواد والمقررات ==================== -->
        <div id="tab-courses" class="tab-panel space-y-6">
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <!-- نموذج إضافة مادة -->
                <div class="lg:col-span-5 bg-white p-6 rounded-3xl border border-slate-200 shadow-xs h-fit">
                    <h3 class="font-black text-base text-slate-900 mb-4">➕ إضافة مادة / مقرر جديد</h3>
                    <form action="{base_url}/course/add" method="POST" enctype="multipart/form-data" class="space-y-3 text-xs">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="courses">
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">الجامعة:</label>
                            <select name="uni_id" required class="w-full p-3 border rounded-xl bg-white font-bold">{uni_options}</select>
                        </div>
                        <div class="grid grid-cols-2 gap-2.5">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">اسم المادة:</label>
                                <input type="text" name="title" placeholder="مثال: فيزياء عامة 101" required class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">رمز المقرر:</label>
                                <input type="text" name="code" placeholder="مثال: PHYS101" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                        </div>
                        <div class="grid grid-cols-2 gap-2.5">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">الكلية:</label>
                                <input type="text" name="faculty" value="كلية الهندسة" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">الفئة المستهدفة:</label>
                                <input type="text" name="target_audience" value="طلاب وطالبات" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                        </div>
                        <div class="grid grid-cols-2 sm:grid-cols-3 gap-2.5 bg-slate-50 p-3 rounded-2xl border">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">سعر المنهج كامل:</label>
                                <input type="number" step="0.5" name="price" placeholder="150" required class="w-full p-2 border rounded-xl font-bold bg-white">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-500 font-bold">السعر السابق:</label>
                                <input type="number" step="0.5" name="old_price" placeholder="200" value="0" class="w-full p-2 border rounded-xl font-bold bg-white">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">سعر الميد:</label>
                                <input type="number" step="0.5" name="mid_price" placeholder="80" value="80" class="w-full p-2 border rounded-xl font-bold bg-white">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-500 font-bold">سابق (ميد):</label>
                                <input type="number" step="0.5" name="mid_old_price" placeholder="110" value="110" class="w-full p-2 border rounded-xl font-bold bg-white">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">سعر الفاينل:</label>
                                <input type="number" step="0.5" name="final_price" placeholder="100" value="100" class="w-full p-2 border rounded-xl font-bold bg-white">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-500 font-bold">سابق (فاينل):</label>
                                <input type="number" step="0.5" name="final_old_price" placeholder="130" value="130" class="w-full p-2 border rounded-xl font-bold bg-white">
                            </div>
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">صورة غلاف المادة (اختياري):</label>
                            <input type="file" name="cover_file" accept="image/*" class="w-full p-2 border border-dashed rounded-xl bg-slate-50">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">وصف وتفاصيل المادة:</label>
                            <textarea name="desc" rows="3" placeholder="شرح تفصيلي لمحتوى المقرر..." required class="w-full p-2.5 border rounded-xl font-medium"></textarea>
                        </div>
                        <button class="w-full bg-sky-600 hover:bg-sky-700 text-white py-3.5 rounded-2xl font-black text-xs shadow-sm transition">إضافة ونشر المادة 📚</button>
                    </form>
                </div>

                <!-- قائمة المواد الحالية -->
                <div class="lg:col-span-7 bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                    <h3 class="font-black text-base text-slate-900 mb-4">📚 جميع المواد والمقررات ({len(courses)})</h3>
                    <div class="space-y-3">
                        {''.join(courses_html) if courses_html else '<p class="text-xs text-slate-400 text-center py-8">لا توجد مواد مضافة</p>'}
                    </div>
                </div>
            </div>
        </div>

        <!-- ==================== 3. تبويب إدارة المحاضرات والملخصات ==================== -->
        <div id="tab-lessons" class="tab-panel space-y-6">
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div class="lg:col-span-5 bg-white p-6 rounded-3xl border border-slate-200 shadow-xs h-fit">
                    <h3 class="font-black text-base text-slate-900 mb-4">🎬 رفع محاضرة / درس جديد</h3>
                    <form action="{base_url}/lesson/add" method="POST" enctype="multipart/form-data" class="space-y-3 text-xs">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="lessons">
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">اختر المادة:</label>
                            <select name="course_id" required class="w-full p-3 border rounded-xl bg-white font-bold">{course_options}</select>
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">عنوان المحاضرة أو الدرس:</label>
                            <input type="text" name="title" placeholder="مثال: المحاضرة الأولى - أساسيات ومفاهيم" required class="w-full p-3 border rounded-xl font-bold">
                        </div>
                        <div class="bg-slate-50 p-4 rounded-2xl border border-slate-200 space-y-3">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">1. ملف فيديو الشرح (MP4) - اختياري:</label>
                                <input type="file" name="video_file" accept="video/*" class="w-full p-2 border border-dashed rounded-xl bg-white">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">2. ملف الملخص أو الشيت (PDF) - اختياري:</label>
                                <input type="file" name="pdf_file" accept=".pdf" class="w-full p-2 border border-dashed rounded-xl bg-white">
                            </div>
                        </div>
                        <button class="w-full bg-sky-600 hover:bg-sky-700 text-white py-3.5 rounded-2xl font-black text-xs shadow-sm transition">رفع وحفظ المحاضرة 🎬</button>
                    </form>
                </div>

                <div class="lg:col-span-7 bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                    <h3 class="font-black text-base text-slate-900 mb-4">📂 المحاضرات والملخصات المرفوعة ({len(lessons)})</h3>
                    <div class="space-y-3">
                        {''.join(lessons_html) if lessons_html else '<p class="text-xs text-slate-400 text-center py-8">لا توجد محاضرات مرفوعة حالياً</p>'}
                    </div>
                </div>
            </div>
        </div>

        <!-- ==================== 4. تبويب إدارة الأعمال الفصلية والمشاريع ==================== -->
        <div id="tab-works" class="tab-panel space-y-6">
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div class="lg:col-span-5 bg-white p-6 rounded-3xl border border-slate-200 shadow-xs h-fit">
                    <h3 class="font-black text-base text-slate-900 mb-4">📝 إضافة عمل فصلي / مشروع احترافي</h3>
                    <form action="{base_url}/work/add" method="POST" enctype="multipart/form-data" class="space-y-3 text-xs">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="works">
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">عنوان العمل أو المشروع:</label>
                            <input type="text" name="title" placeholder="مثال: مشروع تخرج نظام ذكي بلغة Python" required class="w-full p-3 border rounded-xl font-bold">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">الكلية أو القسم:</label>
                            <input type="text" name="faculty" placeholder="مثال: كلية علوم الحاسب والمعلومات" required class="w-full p-3 border rounded-xl font-bold">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">وصف وتفاصيل العمل:</label>
                            <textarea name="desc" rows="3" placeholder="تفاصيل العمل، المميزات، أو التكليف..." required class="w-full p-3 border rounded-xl font-medium"></textarea>
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">رفع صورة غلاف للعمل (من جهازك):</label>
                            <input type="file" name="cover_img" accept="image/*" class="w-full p-2 border border-dashed rounded-xl bg-slate-50">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">أو رابط صورة خارجي (اختياري):</label>
                            <input type="text" name="cover_url" placeholder="https://..." class="w-full p-2.5 border rounded-xl font-mono text-[11px]">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">ملف مرفق للتحميل (PDF / ZIP / صورة - اختياري):</label>
                            <input type="file" name="work_file" class="w-full p-2 border border-dashed rounded-xl bg-slate-50">
                        </div>
                        <button class="w-full bg-teal-600 hover:bg-teal-700 text-white py-3.5 rounded-2xl font-black text-xs shadow-sm transition">نشر العمل الفصلي 📝</button>
                    </form>
                </div>

                <div class="lg:col-span-7 bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                    <h3 class="font-black text-base text-slate-900 mb-4">📝 الأعمال والمشاريع المنشورة ({len(works)})</h3>
                    <div class="space-y-3">
                        {''.join(works_html) if works_html else '<p class="text-xs text-slate-400 text-center py-8">لا توجد أعمال فصلية منشورة</p>'}
                    </div>
                </div>
            </div>
        </div>

        <!-- ==================== 5. تبويب إدارة الإعلانات والصور والسلايدر ==================== -->
        <div id="tab-ads" class="tab-panel space-y-6">
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div class="lg:col-span-5 bg-white p-6 rounded-3xl border border-slate-200 shadow-xs h-fit">
                    <h3 class="font-black text-base text-slate-900 mb-4">📢 إضافة إعلان / صورة سلايدر / بنر</h3>
                    <form action="{base_url}/ad/add" method="POST" enctype="multipart/form-data" class="space-y-3 text-xs">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="ads">
                        <div class="grid grid-cols-2 gap-2.5">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">نوع ومكان الظهور:</label>
                                <select name="ad_type" class="w-full p-2.5 border rounded-xl font-bold bg-white">
                                    <option value="slider">🖼️ صورة في سلايدر المشاريع</option>
                                    <option value="banner">📢 بنر إعلاني مصور</option>
                                    <option value="ticker">⚡ نص في الشريط المتحرك العلوي</option>
                                </select>
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">الحالة:</label>
                                <select name="is_active" class="w-full p-2.5 border rounded-xl font-bold bg-white">
                                    <option value="1">نشط (يظهر بالموقع)</option>
                                    <option value="0">مخفي</option>
                                </select>
                            </div>
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">العنوان الرئيسي / نص الإعلان:</label>
                            <input type="text" name="title" placeholder="عنوان الصورة أو نص الإعلان المتحرك" required class="w-full p-2.5 border rounded-xl font-bold">
                        </div>
                        <div class="grid grid-cols-2 gap-2.5">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">شارة توضيحية (Badge):</label>
                                <input type="text" name="badge" placeholder="مثال: 🔥 عرض خاص" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">ترتيب الظهور:</label>
                                <input type="number" name="sort_order" value="1" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">وصف فرعي تحت العنوان (اختياري):</label>
                            <input type="text" name="subtitle" placeholder="تفاصيل إضافية تظهر على الصورة..." class="w-full p-2.5 border rounded-xl font-medium">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">رفع صورة من جهازك (للسلايدر أو البنر):</label>
                            <input type="file" name="image_file" accept="image/*" class="w-full p-2 border border-dashed rounded-xl bg-slate-50">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">أو وضع رابط صورة مباشر (URL):</label>
                            <input type="text" name="image_url" placeholder="https://..." class="w-full p-2.5 border rounded-xl font-mono text-[11px]">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">رابط التوجيه عند الضغط (اختياري):</label>
                            <input type="text" name="link_url" placeholder="https://wa.me/..." class="w-full p-2.5 border rounded-xl font-mono text-[11px]">
                        </div>
                        <button class="w-full bg-indigo-600 hover:bg-indigo-700 text-white py-3.5 rounded-2xl font-black text-xs shadow-sm transition">إضافة ونشر الإعلان / الصورة 📢</button>
                    </form>
                </div>

                <div class="lg:col-span-7 bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                    <h3 class="font-black text-base text-slate-900 mb-4">🖼️ جميع الإعلانات وصور السلايدر والشريط العلوي ({len(ads)})</h3>
                    <div class="space-y-3">
                        {''.join(ads_html) if ads_html else '<p class="text-xs text-slate-400 text-center py-8">لا توجد إعلانات مضافة</p>'}
                    </div>
                </div>
            </div>
        </div>

        <!-- ==================== 6. تبويب إدارة الجامعات ==================== -->
        <div id="tab-unis" class="tab-panel space-y-6">
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div class="lg:col-span-5 bg-white p-6 rounded-3xl border border-slate-200 shadow-xs h-fit">
                    <h3 class="font-black text-base text-slate-900 mb-4">🏛️ إضافة جامعة جديدة</h3>
                    <form action="{base_url}/uni/add" method="POST" enctype="multipart/form-data" class="space-y-3 text-xs">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="unis">
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">اسم الجامعة:</label>
                            <input type="text" name="name" placeholder="مثال: جامعة القصيم (QU)" required class="w-full p-3 border rounded-xl font-bold">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">وصف الجامعة:</label>
                            <input type="text" name="desc" placeholder="مثال: شروحات ومقررات جامعة القصيم" class="w-full p-3 border rounded-xl font-medium">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">أيقونة رمزية (في حال عدم رفع شعار):</label>
                            <input type="text" name="logo" value="🏛️" class="w-full p-3 border rounded-xl font-bold">
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">شعار الجامعة (صورة PNG/JPG):</label>
                            <input type="file" name="logo_file" accept="image/*" class="w-full p-2 border border-dashed rounded-xl bg-slate-50">
                        </div>
                        <button class="w-full bg-slate-900 hover:bg-slate-800 text-white py-3.5 rounded-2xl font-black text-xs shadow-sm transition">إضافة الجامعة 🏛️</button>
                    </form>
                </div>

                <div class="lg:col-span-7 bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                    <h3 class="font-black text-base text-slate-900 mb-4">🏛️ الجامعات المعتمدة بالموقع ({len(unis)})</h3>
                    <div class="space-y-3">
                        {''.join(unis_html) if unis_html else '<p class="text-xs text-slate-400 text-center py-8">لا توجد جامعات مضافة</p>'}
                    </div>
                </div>
            </div>
        </div>

        <!-- ==================== 7. تبويب معلومات الموقع والبنوك ==================== -->
        <div id="tab-info" class="tab-panel space-y-6">
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <!-- تعديل معلومات الموقع والمنصة والبنر الرئيسي -->
                <div class="lg:col-span-7 bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                    <h3 class="font-black text-base text-slate-900 mb-4">ℹ️ تعديل معلومات الموقع والأكاديمية والبنرات</h3>
                    <form action="{base_url}/settings/update" method="POST" enctype="multipart/form-data" class="space-y-3 text-xs">
                        <input type="hidden" name="csrf_token" value="{csrf}">
                        <input type="hidden" name="return_tab" value="info">
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">عنوان الموقع (في المتصفح):</label>
                                <input type="text" name="site_name" value="{html.escape(settings.get('site_name', ''))}" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">اسم الأكاديمية / الجهة الشارحة:</label>
                                <input type="text" name="academy_name" value="{html.escape(settings.get('academy_name', ''))}" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                        </div>
                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">رقم الواتساب للتواصل والطلبات:</label>
                                <input type="text" name="whatsapp_number" value="{html.escape(settings.get('whatsapp_number', '966593521664'))}" class="w-full p-2.5 border rounded-xl font-mono font-bold">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">عدد الطلاب المشتركين:</label>
                                <input type="text" name="students_count" value="{html.escape(settings.get('students_count', '+1000'))}" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">تقييم الأكاديمية:</label>
                                <input type="text" name="academy_rating" value="{html.escape(settings.get('academy_rating', '5.0'))}" class="w-full p-2.5 border rounded-xl font-bold">
                            </div>
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">نبذة عن الأكاديمية:</label>
                            <textarea name="academy_bio" rows="2" class="w-full p-2.5 border rounded-xl font-medium">{html.escape(settings.get('academy_bio', ''))}</textarea>
                        </div>
                        <div>
                            <label class="block mb-1 text-slate-700 font-bold">تحديث صورة/شعار الأكاديمية (اختياري):</label>
                            <input type="file" name="avatar_file" accept="image/*" class="w-full p-2 border border-dashed rounded-xl bg-slate-50">
                        </div>

                        <div class="p-4 bg-slate-50 rounded-2xl border space-y-3">
                            <h4 class="font-black text-xs text-slate-800">🎯 نصوص البنر الترحيبي الرئيسي والشريط العلوي:</h4>
                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <div>
                                    <label class="block mb-1 text-slate-600 font-bold">شارة الشريط العلوي:</label>
                                    <input type="text" name="promo_badge" value="{html.escape(settings.get('promo_badge', ''))}" class="w-full p-2 border rounded-xl font-bold bg-white">
                                </div>
                                <div>
                                    <label class="block mb-1 text-slate-600 font-bold">نص الخصم في الشريط العلوي:</label>
                                    <input type="text" name="promo_discount" value="{html.escape(settings.get('promo_discount', ''))}" class="w-full p-2 border rounded-xl font-bold bg-white">
                                </div>
                                <div>
                                    <label class="block mb-1 text-slate-600 font-bold">عنوان صندوق السلايدر:</label>
                                    <input type="text" name="slider_title" value="{html.escape(settings.get('slider_title', ''))}" class="w-full p-2 border rounded-xl font-bold bg-white">
                                </div>
                                <div>
                                    <label class="block mb-1 text-slate-600 font-bold">شارة صندوق السلايدر:</label>
                                    <input type="text" name="slider_badge" value="{html.escape(settings.get('slider_badge', ''))}" class="w-full p-2 border rounded-xl font-bold bg-white">
                                </div>
                                <div>
                                    <label class="block mb-1 text-slate-600 font-bold">شارة البنر الرئيسي 1:</label>
                                    <input type="text" name="hero_badge_1" value="{html.escape(settings.get('hero_badge_1', ''))}" class="w-full p-2 border rounded-xl font-bold bg-white">
                                </div>
                                <div>
                                    <label class="block mb-1 text-slate-600 font-bold">شارة البنر الرئيسي 2:</label>
                                    <input type="text" name="hero_badge_2" value="{html.escape(settings.get('hero_badge_2', ''))}" class="w-full p-2 border rounded-xl font-bold bg-white">
                                </div>
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-600 font-bold">العنوان الكبير للبنر الرئيسي (Hero Title):</label>
                                <input type="text" name="hero_title" value="{html.escape(settings.get('hero_title', ''))}" class="w-full p-2 border rounded-xl font-bold bg-white">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-600 font-bold">الوصف تحت العنوان الرئيسي (Hero Description):</label>
                                <textarea name="hero_desc" rows="2" class="w-full p-2 border rounded-xl font-medium bg-white">{html.escape(settings.get('hero_desc', ''))}</textarea>
                            </div>
                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <div>
                                    <label class="block mb-1 text-slate-600 font-bold">نص التحذير القانوني داخل صفحات المواد:</label>
                                    <input type="text" name="legal_warning" value="{html.escape(settings.get('legal_warning', ''))}" class="w-full p-2 border rounded-xl font-bold bg-white">
                                </div>
                                <div>
                                    <label class="block mb-1 text-slate-600 font-bold">نص الفوتر السفلي:</label>
                                    <input type="text" name="footer_text" value="{html.escape(settings.get('footer_text', ''))}" class="w-full p-2 border rounded-xl font-bold bg-white">
                                </div>
                            </div>
                        </div>

                        <button class="w-full bg-sky-600 hover:bg-sky-700 text-white py-3.5 rounded-2xl font-black text-xs shadow-sm transition">حفظ وتحديث معلومات الموقع 💾</button>
                    </form>
                </div>

                <!-- إدارة الحسابات البنكية -->
                <div class="lg:col-span-5 space-y-6">
                    <div class="bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                        <h3 class="font-black text-base text-slate-900 mb-4">💳 إضافة حساب بنكي للتحويل</h3>
                        <form action="{base_url}/bank/add" method="POST" class="space-y-3 text-xs">
                            <input type="hidden" name="csrf_token" value="{csrf}">
                            <input type="hidden" name="return_tab" value="info">
                            <input type="text" name="bank_name" placeholder="اسم البنك (مثال: مصرف الراجحي)" required class="w-full p-3 border rounded-xl font-bold">
                            <input type="text" name="beneficiary" placeholder="اسم المستفيد الثلاثي" required class="w-full p-3 border rounded-xl font-bold">
                            <input type="text" name="account_num" placeholder="رقم الحساب البنكي" required class="w-full p-3 border rounded-xl font-mono font-bold">
                            <input type="text" name="iban" placeholder="رقم الآيبان IBAN (اختياري)" class="w-full p-3 border rounded-xl font-mono font-bold">
                            <button class="w-full bg-emerald-600 hover:bg-emerald-700 text-white py-3.5 rounded-2xl font-black text-xs shadow-sm transition">إضافة الحساب البنكي 💳</button>
                        </form>
                    </div>

                    <div class="bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                        <h3 class="font-black text-base text-slate-900 mb-4">🏦 الحسابات البنكية المعتمدة ({len(banks)})</h3>
                        <div class="space-y-3">
                            {''.join(banks_html) if banks_html else '<p class="text-xs text-slate-400 text-center py-6">لا توجد حسابات بنكية</p>'}
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- ==================== 8. تبويب حسابات الأدمن وكلمة المرور ==================== -->
        <div id="tab-admins" class="tab-panel space-y-6">
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div class="lg:col-span-5 space-y-6">
                    <!-- تغيير كلمة المرور الخاصة بالأدمن الحالي -->
                    <div class="bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                        <h3 class="font-black text-base text-slate-900 mb-1">🔑 تغيير كلمة المرور الخاصة بك</h3>
                        <p class="text-[11px] text-slate-400 font-bold mb-4">حسابك المسجل حالياً: <span class="text-slate-800 font-mono">@{html.escape(session.get('admin_username', 'admin'))}</span></p>
                        <form action="{base_url}/admins/change-password" method="POST" class="space-y-3 text-xs">
                            <input type="hidden" name="csrf_token" value="{csrf}">
                            <input type="hidden" name="return_tab" value="admins">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">كلمة المرور الحالية:</label>
                                <input type="password" name="current_password" placeholder="أدخل كلمة المرور الحالية للتأكيد" required class="w-full p-3 border rounded-xl font-bold">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">كلمة المرور الجديدة:</label>
                                <input type="password" name="new_password" placeholder="أدخل كلمة المرور الجديدة" required class="w-full p-3 border rounded-xl font-bold">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">تأكيد كلمة المرور الجديدة:</label>
                                <input type="password" name="confirm_password" placeholder="أعد كتابة كلمة المرور الجديدة" required class="w-full p-3 border rounded-xl font-bold">
                            </div>
                            <button class="w-full bg-slate-900 hover:bg-slate-800 text-white py-3.5 rounded-2xl font-black text-xs shadow-sm transition">تحديث كلمة المرور الخاصة بي 🔒</button>
                        </form>
                    </div>

                    <!-- إنشاء حساب أدمن جديد -->
                    <div class="bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                        <h3 class="font-black text-base text-slate-900 mb-4">➕ إنشاء حساب أدمن جديد</h3>
                        <form action="{base_url}/admins/add" method="POST" class="space-y-3 text-xs">
                            <input type="hidden" name="csrf_token" value="{csrf}">
                            <input type="hidden" name="return_tab" value="admins">
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">اسم المستخدم (Username):</label>
                                <input type="text" name="username" placeholder="مثال: admin2" required class="w-full p-3 border rounded-xl font-bold">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">الاسم الكامل / المسمى:</label>
                                <input type="text" name="full_name" placeholder="مثال: مشرف المقررات" required class="w-full p-3 border rounded-xl font-bold">
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">الصلاحية / الدور:</label>
                                <select name="role" class="w-full p-3 border rounded-xl font-bold bg-white">
                                    <option value="مدير عام">مدير عام (كامل الصلاحيات)</option>
                                    <option value="مشرف محتوى">مشرف محتوى</option>
                                    <option value="محرر">محرر</option>
                                </select>
                            </div>
                            <div>
                                <label class="block mb-1 text-slate-700 font-bold">كلمة المرور للحساب الجديد:</label>
                                <input type="password" name="password" placeholder="كلمة مرور قوية" required class="w-full p-3 border rounded-xl font-bold">
                            </div>
                            <button class="w-full bg-sky-600 hover:bg-sky-700 text-white py-3.5 rounded-2xl font-black text-xs shadow-sm transition">إنشاء حساب الأدمن 🛡️</button>
                        </form>
                    </div>
                </div>

                <!-- قائمة حسابات الأدمن المسجلة -->
                <div class="lg:col-span-7 bg-white p-6 rounded-3xl border border-slate-200 shadow-xs">
                    <h3 class="font-black text-base text-slate-900 mb-4">🛡️ حسابات الإدارة المسجلة ({len(admins_list)})</h3>
                    <div class="space-y-3">
                        {''.join(admins_html)}
                    </div>
                </div>
            </div>
        </div>
        '''

        return render_template(
            'admin_base.html',
            content=content,
            admin_base_url=base_url,
            site_url=site_url,
            admin_name=session.get('admin_name', 'المدير العام'),
            admin_username=session.get('admin_username', 'admin')
        )

    # ================= مسارات معالجة البيانات (إضافة / تعديل / حذف) =================

    # --- 1. الاشتراكات والطلبات ---
    @bp.route('/enrollment/status', methods=['POST'])
    @bp.route('/approve-enrollment', methods=['POST'])
    def update_enrollment_status():
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        u_id = request.form.get('user_id')
        c_id = request.form.get('course_id')
        status = request.form.get('status', 'approved')
        conn = get_db()
        conn.execute('UPDATE enrollments SET status=? WHERE user_id=? AND course_id=?', (status, u_id, c_id))
        conn.commit()
        conn.close()
        return redirect_tab('overview', 'تم تحديث حالة الاشتراك بنجاح')

    @bp.route('/enrollment/delete', methods=['POST'])
    def delete_enrollment():
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        u_id = request.form.get('user_id')
        c_id = request.form.get('course_id')
        conn = get_db()
        conn.execute('DELETE FROM enrollments WHERE user_id=? AND course_id=?', (u_id, c_id))
        conn.commit()
        conn.close()
        return redirect_tab('overview', 'تم حذف الاشتراك بنجاح')

    @bp.route('/enrollment/add-manual', methods=['POST'])
    def add_manual_enrollment():
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        student_name = request.form.get('student_name', '').strip()
        course_id = request.form.get('course_id')
        if student_name and course_id:
            conn = get_db()
            c = conn.cursor()
            u = c.execute('SELECT id FROM users WHERE name=?', (student_name,)).fetchone()
            if not u:
                c.execute('INSERT INTO users (name, is_admin) VALUES (?, 0)', (student_name,))
                u_id = c.lastrowid
            else:
                u_id = u['id']
            c.execute('''INSERT INTO enrollments (user_id, course_id, status)
                         VALUES (?, ?, 'approved')
                         ON CONFLICT(user_id, course_id) DO UPDATE SET status='approved' ''',
                      (u_id, course_id))
            conn.commit()
            conn.close()
            return redirect_tab('overview', f'تم تفعيل المادة للطالب ({student_name}) بنجاح')
        return redirect_tab('overview', 'بيانات غير مكتملة', 'error')

    # --- 2. المواد والمقررات (إضافة / تعديل / حذف) ---
    @bp.route('/course/add', methods=['POST'])
    @bp.route('/add-course', methods=['POST'])
    def add_course():
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        uni_id = request.form.get('uni_id')
        title = request.form.get('title', '').strip()
        code = request.form.get('code', '').strip()
        faculty = request.form.get('faculty', 'كلية الهندسة').strip()
        target_audience = request.form.get('target_audience', 'طلاب وطالبات').strip()
        desc = request.form.get('desc', '').strip()
        price = float(request.form.get('price') or 0)
        old_price = float(request.form.get('old_price') or 0)
        mid_price = float(request.form.get('mid_price') or 0)
        mid_old_price = float(request.form.get('mid_old_price') or 0)
        final_price = float(request.form.get('final_price') or 0)
        final_old_price = float(request.form.get('final_old_price') or 0)

        cover_img = save_uploaded_file(request.files.get('cover_file'), 'cover', upload_folder)

        conn = get_db()
        conn.execute('''INSERT INTO courses (uni_id, title, code, desc, price, old_price, mid_price, mid_old_price, final_price, final_old_price, cover_img, faculty, target_audience)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (uni_id, title, code, desc, price, old_price, mid_price, mid_old_price, final_price, final_old_price, cover_img, faculty, target_audience))
        conn.commit()
        conn.close()
        return redirect_tab('courses', f'تمت إضافة المادة ({title}) بنجاح')

    @bp.route('/course/edit/<int:course_id>', methods=['POST'])
    def edit_course(course_id):
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        uni_id = request.form.get('uni_id')
        title = request.form.get('title', '').strip()
        code = request.form.get('code', '').strip()
        faculty = request.form.get('faculty', 'كلية الهندسة').strip()
        target_audience = request.form.get('target_audience', 'طلاب وطالبات').strip()
        desc = request.form.get('desc', '').strip()
        price = float(request.form.get('price') or 0)
        old_price = float(request.form.get('old_price') or 0)
        mid_price = float(request.form.get('mid_price') or 0)
        mid_old_price = float(request.form.get('mid_old_price') or 0)
        final_price = float(request.form.get('final_price') or 0)
        final_old_price = float(request.form.get('final_old_price') or 0)

        conn = get_db()
        old_row = conn.execute('SELECT cover_img FROM courses WHERE id=?', (course_id,)).fetchone()
        new_cover = save_uploaded_file(request.files.get('cover_file'), 'cover', upload_folder)
        if new_cover:
            if old_row and old_row['cover_img']:
                remove_uploaded_file(old_row['cover_img'], upload_folder)
            cover_to_save = new_cover
        else:
            cover_to_save = old_row['cover_img'] if old_row else None

        conn.execute('''UPDATE courses SET uni_id=?, title=?, code=?, desc=?, price=?, old_price=?, mid_price=?, mid_old_price=?, final_price=?, final_old_price=?, cover_img=?, faculty=?, target_audience=?
                        WHERE id=?''',
                     (uni_id, title, code, desc, price, old_price, mid_price, mid_old_price, final_price, final_old_price, cover_to_save, faculty, target_audience, course_id))
        conn.commit()
        conn.close()
        return redirect_tab('courses', f'تم تحديث بيانات المادة ({title}) بنجاح')

    @bp.route('/course/delete/<int:course_id>', methods=['POST'])
    @bp.route('/delete-course/<int:course_id>', methods=['GET', 'POST'])
    def delete_course(course_id):
        if not is_admin_authenticated():
            return redirect(f"{base_url}/login")
        if request.method == 'POST' and not verify_csrf():
            return redirect(f"{base_url}/login")
        conn = get_db()
        c_row = conn.execute('SELECT cover_img FROM courses WHERE id=?', (course_id,)).fetchone()
        if c_row and c_row['cover_img']:
            remove_uploaded_file(c_row['cover_img'], upload_folder)
        lessons = conn.execute('SELECT video_filename, pdf_filename FROM lessons WHERE course_id=?', (course_id,)).fetchall()
        for l in lessons:
            remove_uploaded_file(l['video_filename'], upload_folder)
            remove_uploaded_file(l['pdf_filename'], upload_folder)
        conn.execute('DELETE FROM lessons WHERE course_id=?', (course_id,))
        conn.execute('DELETE FROM enrollments WHERE course_id=?', (course_id,))
        conn.execute('DELETE FROM courses WHERE id=?', (course_id,))
        conn.commit()
        conn.close()
        return redirect_tab('courses', 'تم حذف المادة وجميع ملحقاتها بنجاح')

    # --- 3. المحاضرات والدروس (إضافة / تعديل / حذف) ---
    @bp.route('/lesson/add', methods=['POST'])
    @bp.route('/add-unified-lesson', methods=['POST'])
    def add_lesson():
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        c_id = request.form.get('course_id') or request.form.get('c_id')
        title = request.form.get('title', '').strip()
        video_filename = save_uploaded_file(request.files.get('video_file'), 'vid', upload_folder)
        pdf_filename = save_uploaded_file(request.files.get('pdf_file'), 'pdf', upload_folder)

        conn = get_db()
        conn.execute('INSERT INTO lessons (course_id, title, video_filename, pdf_filename) VALUES (?, ?, ?, ?)',
                     (c_id, title, video_filename, pdf_filename))
        conn.commit()
        conn.close()
        return redirect_tab('lessons', f'تمت إضافة المحاضرة ({title}) بنجاح')

    @bp.route('/lesson/edit/<int:lesson_id>', methods=['POST'])
    def edit_lesson(lesson_id):
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        course_id = request.form.get('course_id')
        title = request.form.get('title', '').strip()

        conn = get_db()
        old_l = conn.execute('SELECT * FROM lessons WHERE id=?', (lesson_id,)).fetchone()
        if not old_l:
            conn.close()
            return redirect_tab('lessons', 'المحاضرة غير موجودة', 'error')

        new_vid = save_uploaded_file(request.files.get('video_file'), 'vid', upload_folder)
        if new_vid:
            remove_uploaded_file(old_l['video_filename'], upload_folder)
            vid_to_save = new_vid
        else:
            vid_to_save = old_l['video_filename']

        new_pdf = save_uploaded_file(request.files.get('pdf_file'), 'pdf', upload_folder)
        if new_pdf:
            remove_uploaded_file(old_l['pdf_filename'], upload_folder)
            pdf_to_save = new_pdf
        else:
            pdf_to_save = old_l['pdf_filename']

        conn.execute('UPDATE lessons SET course_id=?, title=?, video_filename=?, pdf_filename=? WHERE id=?',
                     (course_id, title, vid_to_save, pdf_to_save, lesson_id))
        conn.commit()
        conn.close()
        return redirect_tab('lessons', f'تم تعديل المحاضرة ({title}) بنجاح')

    @bp.route('/lesson/delete/<int:lesson_id>', methods=['POST'])
    @bp.route('/delete-lesson/<int:lesson_id>', methods=['GET', 'POST'])
    def delete_lesson(lesson_id):
        if not is_admin_authenticated():
            return redirect(f"{base_url}/login")
        if request.method == 'POST' and not verify_csrf():
            return redirect(f"{base_url}/login")
        conn = get_db()
        old_l = conn.execute('SELECT video_filename, pdf_filename FROM lessons WHERE id=?', (lesson_id,)).fetchone()
        if old_l:
            remove_uploaded_file(old_l['video_filename'], upload_folder)
            remove_uploaded_file(old_l['pdf_filename'], upload_folder)
        conn.execute('DELETE FROM lessons WHERE id=?', (lesson_id,))
        conn.commit()
        conn.close()
        return redirect_tab('lessons', 'تم حذف المحاضرة بنجاح')

    # --- 4. الأعمال الفصلية والمشاريع (إضافة / تعديل / حذف) ---
    @bp.route('/work/add', methods=['POST'])
    @bp.route('/add-work', methods=['POST'])
    def add_work():
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        title = request.form.get('title', '').strip()
        faculty = request.form.get('faculty', '').strip()
        desc = request.form.get('desc', '').strip()
        cover_url = request.form.get('cover_url', '').strip()

        uploaded_cover = save_uploaded_file(request.files.get('cover_img'), 'work_cover', upload_folder)
        cover_to_save = uploaded_cover if uploaded_cover else (cover_url if cover_url else None)
        work_file = save_uploaded_file(request.files.get('work_file'), 'work', upload_folder)

        conn = get_db()
        conn.execute('INSERT INTO semester_works (title, faculty, desc, file_name, cover_img) VALUES (?, ?, ?, ?, ?)',
                     (title, faculty, desc, work_file, cover_to_save))
        conn.commit()
        conn.close()
        return redirect_tab('works', f'تم نشر العمل الفصلي ({title}) بنجاح')

    @bp.route('/work/edit/<int:work_id>', methods=['POST'])
    def edit_work(work_id):
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        title = request.form.get('title', '').strip()
        faculty = request.form.get('faculty', '').strip()
        desc = request.form.get('desc', '').strip()
        cover_url = request.form.get('cover_url', '').strip()

        conn = get_db()
        old_w = conn.execute('SELECT * FROM semester_works WHERE id=?', (work_id,)).fetchone()
        if not old_w:
            conn.close()
            return redirect_tab('works', 'العمل غير موجود', 'error')

        new_cover = save_uploaded_file(request.files.get('cover_img'), 'work_cover', upload_folder)
        if new_cover:
            remove_uploaded_file(old_w['cover_img'], upload_folder)
            cover_to_save = new_cover
        elif cover_url:
            cover_to_save = cover_url
        else:
            cover_to_save = old_w['cover_img']

        new_file = save_uploaded_file(request.files.get('work_file'), 'work', upload_folder)
        if new_file:
            remove_uploaded_file(old_w['file_name'], upload_folder)
            file_to_save = new_file
        else:
            file_to_save = old_w['file_name']

        conn.execute('UPDATE semester_works SET title=?, faculty=?, desc=?, file_name=?, cover_img=? WHERE id=?',
                     (title, faculty, desc, file_to_save, cover_to_save, work_id))
        conn.commit()
        conn.close()
        return redirect_tab('works', f'تم تحديث العمل الفصلي ({title}) بنجاح')

    @bp.route('/work/delete/<int:work_id>', methods=['POST'])
    @bp.route('/delete-work/<int:work_id>', methods=['GET', 'POST'])
    def delete_work(work_id):
        if not is_admin_authenticated():
            return redirect(f"{base_url}/login")
        if request.method == 'POST' and not verify_csrf():
            return redirect(f"{base_url}/login")
        conn = get_db()
        old_w = conn.execute('SELECT file_name, cover_img FROM semester_works WHERE id=?', (work_id,)).fetchone()
        if old_w:
            remove_uploaded_file(old_w['file_name'], upload_folder)
            remove_uploaded_file(old_w['cover_img'], upload_folder)
        conn.execute('DELETE FROM semester_works WHERE id=?', (work_id,))
        conn.commit()
        conn.close()
        return redirect_tab('works', 'تم حذف العمل الفصلي بنجاح')

    # --- 5. الإعلانات والصور والسلايدر (إضافة / تعديل / حذف) ---
    @bp.route('/ad/add', methods=['POST'])
    def add_ad():
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        ad_type = request.form.get('ad_type', 'slider').strip()
        is_active = int(request.form.get('is_active', 1))
        title = request.form.get('title', '').strip()
        subtitle = request.form.get('subtitle', '').strip()
        badge = request.form.get('badge', '').strip()
        sort_order = int(request.form.get('sort_order') or 1)
        link_url = request.form.get('link_url', '').strip()
        image_url_input = request.form.get('image_url', '').strip()

        uploaded_img = save_uploaded_file(request.files.get('image_file'), 'ad', upload_folder)
        final_image = uploaded_img if uploaded_img else image_url_input

        conn = get_db()
        conn.execute('''INSERT INTO ads_banners (title, subtitle, badge, image_url, link_url, ad_type, is_active, sort_order)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (title, subtitle, badge, final_image, link_url, ad_type, is_active, sort_order))
        conn.commit()
        conn.close()
        return redirect_tab('ads', 'تمت إضافة الإعلان / الصورة بنجاح')

    @bp.route('/ad/edit/<int:ad_id>', methods=['POST'])
    def edit_ad(ad_id):
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        ad_type = request.form.get('ad_type', 'slider').strip()
        is_active = int(request.form.get('is_active', 1))
        title = request.form.get('title', '').strip()
        subtitle = request.form.get('subtitle', '').strip()
        badge = request.form.get('badge', '').strip()
        sort_order = int(request.form.get('sort_order') or 1)
        link_url = request.form.get('link_url', '').strip()
        image_url_input = request.form.get('image_url', '').strip()

        conn = get_db()
        old_ad = conn.execute('SELECT * FROM ads_banners WHERE id=?', (ad_id,)).fetchone()
        if not old_ad:
            conn.close()
            return redirect_tab('ads', 'الإعلان غير موجود', 'error')

        uploaded_img = save_uploaded_file(request.files.get('image_file'), 'ad', upload_folder)
        if uploaded_img:
            remove_uploaded_file(old_ad['image_url'], upload_folder)
            final_image = uploaded_img
        elif image_url_input:
            final_image = image_url_input
        else:
            final_image = old_ad['image_url']

        conn.execute('''UPDATE ads_banners SET title=?, subtitle=?, badge=?, image_url=?, link_url=?, ad_type=?, is_active=?, sort_order=?
                        WHERE id=?''',
                     (title, subtitle, badge, final_image, link_url, ad_type, is_active, sort_order, ad_id))
        conn.commit()
        conn.close()
        return redirect_tab('ads', 'تم تعديل الإعلان / الصورة بنجاح')

    @bp.route('/ad/delete/<int:ad_id>', methods=['POST'])
    def delete_ad(ad_id):
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        conn = get_db()
        old_ad = conn.execute('SELECT image_url FROM ads_banners WHERE id=?', (ad_id,)).fetchone()
        if old_ad and old_ad['image_url']:
            remove_uploaded_file(old_ad['image_url'], upload_folder)
        conn.execute('DELETE FROM ads_banners WHERE id=?', (ad_id,))
        conn.commit()
        conn.close()
        return redirect_tab('ads', 'تم حذف الإعلان / الصورة بنجاح')

    # --- 6. الجامعات (إضافة / تعديل / حذف) ---
    @bp.route('/uni/add', methods=['POST'])
    @bp.route('/add-uni', methods=['POST'])
    def add_uni():
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        name = request.form.get('name', '').strip()
        desc = request.form.get('desc', '').strip()
        logo = request.form.get('logo', '🏛️').strip() or '🏛️'
        logo_img = save_uploaded_file(request.files.get('logo_file'), 'uni_logo', upload_folder)

        conn = get_db()
        conn.execute('INSERT INTO universities (name, logo, desc, logo_img) VALUES (?, ?, ?, ?)',
                     (name, logo, desc, logo_img))
        conn.commit()
        conn.close()
        return redirect_tab('unis', f'تمت إضافة الجامعة ({name}) بنجاح')

    @bp.route('/uni/edit/<int:uni_id>', methods=['POST'])
    def edit_uni(uni_id):
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        name = request.form.get('name', '').strip()
        desc = request.form.get('desc', '').strip()
        logo = request.form.get('logo', '🏛️').strip() or '🏛️'

        conn = get_db()
        old_u = conn.execute('SELECT * FROM universities WHERE id=?', (uni_id,)).fetchone()
        if not old_u:
            conn.close()
            return redirect_tab('unis', 'الجامعة غير موجودة', 'error')

        new_logo_img = save_uploaded_file(request.files.get('logo_file'), 'uni_logo', upload_folder)
        if new_logo_img:
            remove_uploaded_file(old_u['logo_img'], upload_folder)
            logo_to_save = new_logo_img
        else:
            logo_to_save = old_u['logo_img']

        conn.execute('UPDATE universities SET name=?, logo=?, desc=?, logo_img=? WHERE id=?',
                     (name, logo, desc, logo_to_save, uni_id))
        conn.commit()
        conn.close()
        return redirect_tab('unis', f'تم تعديل بيانات الجامعة ({name}) بنجاح')

    @bp.route('/uni/delete/<int:uni_id>', methods=['POST'])
    @bp.route('/delete-uni/<int:uni_id>', methods=['GET', 'POST'])
    def delete_uni(uni_id):
        if not is_admin_authenticated():
            return redirect(f"{base_url}/login")
        if request.method == 'POST' and not verify_csrf():
            return redirect(f"{base_url}/login")
        conn = get_db()
        old_u = conn.execute('SELECT logo_img FROM universities WHERE id=?', (uni_id,)).fetchone()
        if old_u and old_u['logo_img']:
            remove_uploaded_file(old_u['logo_img'], upload_folder)
        conn.execute('DELETE FROM universities WHERE id=?', (uni_id,))
        conn.execute('DELETE FROM courses WHERE uni_id=?', (uni_id,))
        conn.commit()
        conn.close()
        return redirect_tab('unis', 'تم حذف الجامعة بنجاح')

    # --- 7. معلومات الموقع والحسابات البنكية ---
    @bp.route('/settings/update', methods=['POST'])
    def update_settings():
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        keys = [
            'site_name', 'academy_name', 'academy_bio', 'whatsapp_number',
            'students_count', 'academy_rating', 'promo_badge', 'promo_discount',
            'slider_title', 'slider_badge', 'hero_badge_1', 'hero_badge_2',
            'hero_title', 'hero_desc', 'legal_warning', 'footer_text'
        ]
        conn = get_db()
        for k in keys:
            if k in request.form:
                val = request.form.get(k, '').strip()
                conn.execute('INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=?',
                             (k, val, val))

        # تحديث جدول instructors أيضاً لصفحة "عن الأكاديمية"
        ac_name = request.form.get('academy_name', '').strip()
        ac_bio = request.form.get('academy_bio', '').strip()
        ac_rating = float(request.form.get('academy_rating') or 5.0)
        avatar_img = save_uploaded_file(request.files.get('avatar_file'), 'avatar', upload_folder)
        if avatar_img:
            conn.execute('UPDATE instructors SET name=?, bio=?, rating=?, avatar_img=? WHERE id=1',
                         (ac_name, ac_bio, ac_rating, avatar_img))
        else:
            conn.execute('UPDATE instructors SET name=?, bio=?, rating=? WHERE id=1',
                         (ac_name, ac_bio, ac_rating))

        conn.commit()
        conn.close()
        return redirect_tab('info', 'تم حفظ وتحديث معلومات الموقع والمنصة بنجاح')

    @bp.route('/bank/add', methods=['POST'])
    @bp.route('/add-bank', methods=['POST'])
    def add_bank():
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        bank_name = request.form.get('bank_name', '').strip()
        beneficiary = request.form.get('beneficiary', '').strip()
        account_num = request.form.get('account_num', '').strip()
        iban = request.form.get('iban', '').strip()
        conn = get_db()
        conn.execute('INSERT INTO bank_accounts (bank_name, beneficiary, account_num, iban) VALUES (?, ?, ?, ?)',
                     (bank_name, beneficiary, account_num, iban))
        conn.commit()
        conn.close()
        return redirect_tab('info', 'تمت إضافة الحساب البنكي بنجاح')

    @bp.route('/bank/edit/<int:bank_id>', methods=['POST'])
    def edit_bank(bank_id):
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        bank_name = request.form.get('bank_name', '').strip()
        beneficiary = request.form.get('beneficiary', '').strip()
        account_num = request.form.get('account_num', '').strip()
        iban = request.form.get('iban', '').strip()
        conn = get_db()
        conn.execute('UPDATE bank_accounts SET bank_name=?, beneficiary=?, account_num=?, iban=? WHERE id=?',
                     (bank_name, beneficiary, account_num, iban, bank_id))
        conn.commit()
        conn.close()
        return redirect_tab('info', 'تم تعديل الحساب البنكي بنجاح')

    @bp.route('/bank/delete/<int:bank_id>', methods=['POST'])
    @bp.route('/delete-bank/<int:bank_id>', methods=['GET', 'POST'])
    def delete_bank(bank_id):
        if not is_admin_authenticated():
            return redirect(f"{base_url}/login")
        if request.method == 'POST' and not verify_csrf():
            return redirect(f"{base_url}/login")
        conn = get_db()
        conn.execute('DELETE FROM bank_accounts WHERE id=?', (bank_id,))
        conn.commit()
        conn.close()
        return redirect_tab('info', 'تم حذف الحساب البنكي بنجاح')

    # --- 8. إدارة حسابات الأدمن وتغيير كلمة المرور ---
    @bp.route('/admins/change-password', methods=['POST'])
    def change_own_password():
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        current_pw = request.form.get('current_password', '').strip()
        new_pw = request.form.get('new_password', '').strip()
        confirm_pw = request.form.get('confirm_password', '').strip()

        if not new_pw or len(new_pw) < 3:
            return redirect_tab('admins', 'كلمة المرور الجديدة قصيرة جداً', 'error')
        if new_pw != confirm_pw:
            return redirect_tab('admins', 'كلمة المرور الجديدة وتأكيدها غير متطابقين!', 'error')

        conn = get_db()
        adm = conn.execute('SELECT * FROM admins WHERE id=?', (session['admin_id'],)).fetchone()
        if not adm or not check_password_hash(adm['password_hash'], current_pw):
            conn.close()
            return redirect_tab('admins', 'كلمة المرور الحالية غير صحيحة!', 'error')

        new_hash = generate_password_hash(new_pw, method='pbkdf2:sha256')
        conn.execute('UPDATE admins SET password_hash=? WHERE id=?', (new_hash, session['admin_id']))
        conn.commit()
        conn.close()
        return redirect_tab('admins', 'تم تغيير كلمة المرور الخاصة بك بنجاح 🔒')

    @bp.route('/admins/add', methods=['POST'])
    def add_admin_account():
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        username = request.form.get('username', '').strip()
        full_name = request.form.get('full_name', '').strip() or 'مدير النظام'
        role = request.form.get('role', 'مدير عام').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            return redirect_tab('admins', 'يرجى إدخال اسم المستخدم وكلمة المرور', 'error')

        conn = get_db()
        existing = conn.execute('SELECT id FROM admins WHERE username=?', (username,)).fetchone()
        if existing:
            conn.close()
            return redirect_tab('admins', f'اسم المستخدم ({username}) مستخدم بالفعل!', 'error')

        pw_hash = generate_password_hash(password, method='pbkdf2:sha256')
        conn.execute('INSERT INTO admins (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)',
                     (username, pw_hash, full_name, role))
        conn.commit()
        conn.close()
        return redirect_tab('admins', f'تم إنشاء حساب الأدمن (@{username}) بنجاح 🛡️')

    @bp.route('/admins/edit/<int:adm_id>', methods=['POST'])
    def edit_admin_account(adm_id):
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        username = request.form.get('username', '').strip()
        full_name = request.form.get('full_name', '').strip()
        role = request.form.get('role', 'مدير عام').strip()
        new_pw = request.form.get('new_password', '').strip()

        conn = get_db()
        dup = conn.execute('SELECT id FROM admins WHERE username=? AND id!=?', (username, adm_id)).fetchone()
        if dup:
            conn.close()
            return redirect_tab('admins', f'اسم المستخدم ({username}) محجوز لحساب آخر!', 'error')

        if new_pw:
            pw_hash = generate_password_hash(new_pw, method='pbkdf2:sha256')
            conn.execute('UPDATE admins SET username=?, full_name=?, role=?, password_hash=? WHERE id=?',
                         (username, full_name, role, pw_hash, adm_id))
        else:
            conn.execute('UPDATE admins SET username=?, full_name=?, role=? WHERE id=?',
                         (username, full_name, role, adm_id))
        conn.commit()
        conn.close()
        return redirect_tab('admins', f'تم تحديث بيانات حساب الأدمن (@{username}) بنجاح')

    @bp.route('/admins/delete/<int:adm_id>', methods=['POST'])
    def delete_admin_account(adm_id):
        if not is_admin_authenticated() or not verify_csrf():
            return redirect(f"{base_url}/login")
        if adm_id == session.get('admin_id'):
            return redirect_tab('admins', 'لا يمكنك حذف حسابك الشخصي أثناء تسجيل الدخول!', 'error')
        conn = get_db()
        total_admins = conn.execute('SELECT COUNT(*) FROM admins').fetchone()[0]
        if total_admins <= 1:
            conn.close()
            return redirect_tab('admins', 'لا يمكن حذف الحساب الوحيد المتبقي في النظام!', 'error')
        conn.execute('DELETE FROM admins WHERE id=?', (adm_id,))
        conn.commit()
        conn.close()
        return redirect_tab('admins', 'تم حذف حساب الأدمن بنجاح')

    app.register_blueprint(bp, url_prefix=url_prefix)
