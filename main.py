import os
import time
from flask import Flask, render_template, redirect, url_for, request, session, send_from_directory, Response, stream_with_context, make_response
from database import get_db, init_db, get_site_settings
from admin_panel import register_admin_routes, is_admin_authenticated

app = Flask(__name__)
app.config['SECRET_KEY'] = 'itqan-bravo-fixed-admin-2026-ultra-secure'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

ADMIN_SECRET_PATH = "itqan-secure-panel-2026"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

# تهيئة قاعدة البيانات تلقائياً
init_db()

# تسجيل مسارات لوحة التحكم الآمنة (على المسار السري وعلى /admin)
register_admin_routes(app, url_prefix=f'/{ADMIN_SECRET_PATH}', site_url='/', blueprint_name='admin_secret_bp', upload_folder=UPLOAD_FOLDER)
register_admin_routes(app, url_prefix='/admin', site_url='/', blueprint_name='admin_std_bp', upload_folder=UPLOAD_FOLDER)


@app.context_processor
def inject_global_site_data():
    conn = get_db()
    settings = get_site_settings(conn)
    slider_ads = conn.execute("SELECT * FROM ads_banners WHERE ad_type='slider' AND is_active=1 ORDER BY sort_order ASC, id DESC").fetchall()
    ticker_ads = conn.execute("SELECT * FROM ads_banners WHERE ad_type='ticker' AND is_active=1 ORDER BY sort_order ASC, id DESC").fetchall()
    banner_ads = conn.execute("SELECT * FROM ads_banners WHERE ad_type='banner' AND is_active=1 ORDER BY sort_order ASC, id DESC").fetchall()
    conn.close()
    return dict(
        site_settings=settings,
        slider_ads=slider_ads,
        ticker_ads=ticker_ads,
        banner_ads=banner_ads
    )


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ==========================================
# دوال الحماية الجديدة لمنع تحميل الفيديو والملخصات
# ==========================================
@app.route('/stream_video/<filename>')
def stream_video(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        return "الملف غير موجود", 404

    def generate():
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(4096 * 10)  # قراءة 40 كيلوبايت في كل مرة
                if not data:
                    break
                yield data

    response = Response(stream_with_context(generate()), mimetype="video/mp4")
    response.headers["Content-Disposition"] = "inline"  # يمنع التحميل كملف
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route('/stream_pdf/<filename>')
def stream_pdf(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        return "الملف غير موجود", 404
    response = make_response(send_from_directory(app.config['UPLOAD_FOLDER'], filename))
    response.headers["Content-Disposition"] = "inline"  # منع التحميل المباشر
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
# ==========================================


@app.route('/')
def home():
    conn = get_db()
    settings = get_site_settings(conn)
    wa_num = settings.get('whatsapp_number', '966593521664')
    academy_name = settings.get('academy_name', 'أكاديمية إتقان')
    hero_badge_1 = settings.get('hero_badge_1', '🏆 المنصة التعليمية الأولى')
    hero_badge_2 = settings.get('hero_badge_2', 'أكاديمية إتقان 2026')
    hero_title = settings.get('hero_title', 'شروحات جامعية، أعمال فصلية، ومشاريع احترافية بامتياز A+ 🎯')
    hero_desc = settings.get('hero_desc', 'نقدم أفضل الملخصات، الواجبات، الأنشطة والأعمال الفصلية المعتمدة لجميع الجامعات والمقررات باللغتين العربية والإنجليزية.')

    unis = conn.execute('SELECT * FROM universities').fetchall()
    courses = conn.execute('''
        SELECT c.*, u.name as uni_name,
               (SELECT COUNT(*) FROM lessons l WHERE l.course_id = c.id) as lesson_count
        FROM courses c 
        LEFT JOIN universities u ON c.uni_id=u.id 
        ORDER BY c.id DESC
    ''').fetchall()

    # جلب جميع الأعمال والمشاريع الاحترافية المميزة
    works = conn.execute('SELECT * FROM semester_works ORDER BY id DESC').fetchall()

    uni_cards = []
    for idx, u in enumerate(unis):
        c_count = conn.execute('SELECT COUNT(*) FROM courses WHERE uni_id=?', (u['id'],)).fetchone()[0]
        logo_img = u['logo_img'] if 'logo_img' in u.keys() else None
        logo_html = f'<img src="/uploads/{logo_img}" class="w-14 h-14 object-contain">' if logo_img else f'<span class="text-3xl">{u["logo"] or "🏛️"}</span>'

        card_bg = "bg-[#1E293B] text-white" if idx % 2 == 1 else "bg-[#F4F6F8] text-slate-900"
        text_title = "text-white" if idx % 2 == 1 else "text-slate-900"
        text_sub = "text-slate-300" if idx % 2 == 1 else "text-slate-500"
        badge_bg = "bg-white text-slate-900"

        uni_cards.append(f'''
        <a href="/uni/{u['id']}" class="relative block {card_bg} rounded-[32px] pt-12 pb-6 px-6 text-center shadow-sm hover:shadow-xl transition-all duration-300 hover:-translate-y-1 border border-slate-200/60">
            <div class="absolute -top-7 left-1/2 -translate-x-1/2 w-16 h-16 {badge_bg} rounded-2xl shadow-md flex items-center justify-center overflow-hidden border-4 border-white">
                {logo_html}
            </div>
            <h3 class="font-black text-base mb-1 {text_title}">{u['name']}</h3>
            <p class="text-xs font-bold {text_sub}">{c_count} مادة تعليمية &lsaquo;</p>
        </a>''')

    # تصميم إبداعي وجديد كلياً لبطاقات المقررات والملخصات
    course_gradients = [
        "from-indigo-600 via-blue-600 to-cyan-500",
        "from-emerald-600 via-teal-600 to-cyan-600",
        "from-violet-600 via-purple-600 to-fuchsia-500",
        "from-amber-500 via-orange-500 to-rose-500",
    ]
    course_cards = []
    for idx, c in enumerate(courses):
        grad = course_gradients[idx % len(course_gradients)]
        if c['cover_img']:
            cover_Src = c['cover_img'] if c['cover_img'].startswith('http') else f"/uploads/{c['cover_img']}"
            cover_tag = f'<img src="{cover_Src}" class="w-full h-52 object-cover group-hover:scale-110 transition-transform duration-500">'
        else:
            cover_tag = f'''
            <div class="w-full h-52 bg-gradient-to-br {grad} flex flex-col items-center justify-center relative overflow-hidden p-6 text-center">
                <div class="absolute -top-10 -right-10 w-32 h-32 bg-white/10 rounded-full blur-xl"></div>
                <div class="absolute -bottom-10 -left-10 w-32 h-32 bg-black/10 rounded-full blur-xl"></div>
                <div class="w-16 h-16 bg-white/20 backdrop-blur-md rounded-2xl border border-white/30 flex items-center justify-center text-3xl shadow-lg mb-2 group-hover:scale-110 transition-transform duration-300">📚</div>
                <span class="text-white/90 text-xs font-black tracking-wide">{c["code"] or "ITQAN COURSE"}</span>
            </div>'''

        uni_name = c['uni_name'] or 'جامعة معتمدة'
        code_val = c['code'] if ('code' in c.keys() and c['code']) else 'مقرر جامعي'
        faculty_name = c['faculty'] if ('faculty' in c.keys() and c['faculty']) else 'كلية الهندسة'
        lesson_count = c['lesson_count'] if 'lesson_count' in c.keys() else 0
        old_p = c['old_price'] if ('old_price' in c.keys() and c['old_price']) else 0
        mid_p = c['mid_price'] if ('mid_price' in c.keys() and c['mid_price']) else 0
        fin_p = c['final_price'] if ('final_price' in c.keys() and c['final_price']) else 0

        old_price_html = f'<span class="text-xs text-slate-400 line-through font-bold mr-1">{old_p:g} ر.س</span>' if old_p > 0 else ''

        # تم إزالة أزرار الأدمن من الواجهة هنا
        admin_course_bar = ''

        course_cards.append(f'''
        <div class="group bg-white rounded-[28px] border border-slate-200/80 shadow-sm hover:shadow-2xl hover:-translate-y-1.5 transition-all duration-300 flex flex-col justify-between overflow-hidden relative">
            <div>
                <!-- رأس البطاقة والصورة -->
                <div class="relative overflow-hidden h-52">
                    {cover_tag}
                    <div class="absolute inset-0 bg-gradient-to-t from-slate-950/80 via-slate-950/20 to-transparent"></div>
                    
                    <!-- شارات علوية -->
                    <div class="absolute top-3.5 right-3.5 left-3.5 flex items-center justify-between gap-2">
                        <span class="bg-white/95 backdrop-blur-md text-slate-900 text-[11px] font-black px-3 py-1 rounded-full shadow-sm border border-white/50">
                            🏛️ {uni_name}
                        </span>
                        <span class="bg-slate-900/85 backdrop-blur-md text-amber-300 text-[11px] font-mono font-black px-3 py-1 rounded-full border border-amber-400/30">
                            {code_val}
                        </span>
                    </div>

                    <!-- شريط سفلي داخل الصورة -->
                    <div class="absolute bottom-3 right-3.5 left-3.5 flex items-center justify-between text-white">
                        <span class="bg-teal-500/90 backdrop-blur-xs text-slate-950 text-[11px] font-black px-3 py-1 rounded-full shadow-xs">
                            {faculty_name}
                        </span>
                        <div class="flex items-center gap-2 text-xs font-black bg-slate-900/75 backdrop-blur-xs px-3 py-1 rounded-full border border-white/15">
                            <span>📖 {lesson_count} درس</span>
                            <span class="text-amber-400">★ 5.0</span>
                        </div>
                    </div>
                </div>

                <!-- محتوى البطاقة -->
                <div class="p-5">
                    <h3 class="font-black text-lg text-slate-900 group-hover:text-teal-700 transition leading-snug mb-2">
                        {c['title']}
                    </h3>
                    <p class="text-xs text-slate-500 line-clamp-2 leading-relaxed mb-4">
                        {c['desc']}
                    </p>

                    <!-- شريط أسعار الباقات المصغر -->
                    <div class="grid grid-cols-3 gap-1.5 bg-slate-50 p-2 rounded-2xl border border-slate-100 text-center mb-4">
                        <div class="bg-white p-1.5 rounded-xl border border-teal-200/80 shadow-2xs">
                            <span class="block text-[10px] text-slate-400 font-bold">المنهج كامل</span>
                            <span class="font-black text-xs text-teal-700">{c['price']:g} ر.س</span>
                        </div>
                        <div class="p-1.5 rounded-xl">
                            <span class="block text-[10px] text-slate-400 font-bold">باقة الميد</span>
                            <span class="font-black text-xs text-slate-700">{mid_p:g} ر.س</span>
                        </div>
                        <div class="p-1.5 rounded-xl">
                            <span class="block text-[10px] text-slate-400 font-bold">باقة الفاينل</span>
                            <span class="font-black text-xs text-slate-700">{fin_p:g} ر.س</span>
                        </div>
                    </div>
                </div>
            </div>

            <div>
                <!-- فوتر البطاقة -->
                <div class="px-5 pb-5 pt-3 border-t border-slate-100 flex items-center justify-between gap-3">
                    <div>
                        <span class="text-[10px] text-slate-400 font-bold block">السعر المعتمد</span>
                        <div class="flex items-baseline gap-1">
                            <span class="text-xl font-black text-slate-900">{c['price']:g}</span>
                            <span class="text-xs font-bold text-teal-600">ر.س</span>
                            {old_price_html}
                        </div>
                    </div>
                    <a href="/course/{c['id']}" class="bg-gradient-to-l from-[#0F172A] to-[#0B4B80] hover:from-teal-500 hover:to-emerald-500 text-white hover:text-slate-950 text-xs font-black px-5 py-3 rounded-2xl shadow-md transition-all duration-200 flex items-center gap-1.5">
                        <span>تصفح المقرر</span>
                        <span>&lsaquo;</span>
                    </a>
                </div>
                {admin_course_bar}
            </div>
        </div>''')

    # تصميم إبداعي احترافي لعرض الأعمال والمشاريع الاحترافية المميزة
    featured_works_cards = []
    for idx, w in enumerate(works):
        file_link = f'/uploads/{w["file_name"]}' if w['file_name'] else '#'
        download_btn = f'''
        <a href="{file_link}" target="_blank" class="bg-slate-100 hover:bg-teal-50 text-slate-800 hover:text-teal-700 border border-slate-200 text-xs font-black px-3.5 py-2.5 rounded-2xl flex items-center gap-1.5 transition shrink-0" title="تحميل الملف المرفق">
            <span>المرفق</span>
            <span>📥</span>
        </a>''' if w['file_name'] else ''

        wa_work_msg = f"مرحباً، أود الاستفسار عن العمل الفصلي/المشروع ({w['title']}) عبر منصة إتقان."
        wa_work_link = f"https://wa.me/{wa_num}?text={wa_work_msg}"

        if w['cover_img']:
            img_url = w['cover_img'] if w['cover_img'].startswith('http') else f'/uploads/{w["cover_img"]}'
            cover_tag = f'<img src="{img_url}" class="w-full h-52 object-cover group-hover:scale-110 transition-transform duration-500">'
        else:
            cover_tag = '''
            <div class="w-full h-52 bg-gradient-to-br from-teal-600 via-emerald-600 to-sky-700 flex flex-col items-center justify-center text-white p-6 relative overflow-hidden">
                <div class="w-16 h-16 rounded-2xl bg-white/15 backdrop-blur-md flex items-center justify-center text-3xl mb-2 border border-white/25">🚀</div>
                <span class="text-xs font-black text-teal-100">مشروع أكاديمي معتمد</span>
            </div>'''

        # تم إزالة أزرار الأدمن من الواجهة هنا
        admin_work_bar = ''

        featured_works_cards.append(f'''
        <div class="group bg-white rounded-[28px] border border-slate-200/80 shadow-sm hover:shadow-2xl hover:-translate-y-1.5 transition-all duration-300 flex flex-col justify-between overflow-hidden">
            <div>
                <div class="relative overflow-hidden h-52">
                    {cover_tag}
                    <div class="absolute inset-0 bg-gradient-to-t from-slate-950/85 via-slate-950/25 to-transparent"></div>
                    <div class="absolute top-3.5 right-3.5 left-3.5 flex items-center justify-between gap-2">
                        <span class="bg-amber-400 text-slate-950 text-[11px] font-black px-3.5 py-1 rounded-full shadow-sm">
                            {w['faculty']}
                        </span>
                        <span class="bg-emerald-500/90 backdrop-blur-md text-white text-[10px] font-black px-3 py-1 rounded-full shadow-sm">
                            ✨ متاح للتنفيذ الفوري
                        </span>
                    </div>
                    <div class="absolute bottom-3 right-4 left-4 flex items-center justify-between text-white/90 text-[11px] font-bold">
                        <span>🎯 ضمان جودة وامتياز A+</span>
                        <span>#{idx + 1}</span>
                    </div>
                </div>

                <div class="p-5">
                    <h3 class="font-black text-base sm:text-lg text-slate-900 group-hover:text-emerald-700 transition leading-snug mb-2">
                        {w['title']}
                    </h3>
                    <p class="text-xs text-slate-500 line-clamp-3 leading-relaxed mb-4">
                        {w['desc']}
                    </p>
                    <div class="flex items-center gap-2 flex-wrap">
                        <span class="text-[10px] font-bold bg-slate-100 text-slate-600 px-2.5 py-1 rounded-lg">✅ شامل التوثيق والشرح</span>
                        <span class="text-[10px] font-bold bg-teal-50 text-teal-700 px-2.5 py-1 rounded-lg">⚡ تسليم سريع</span>
                    </div>
                </div>
            </div>

            <div>
                <div class="px-5 pb-5 pt-3 border-t border-slate-100 flex items-center justify-between gap-2">
                    <a href="{wa_work_link}" target="_blank" class="flex-grow bg-gradient-to-l from-emerald-600 to-teal-500 hover:from-emerald-500 hover:to-teal-400 text-white text-xs font-black py-2.5 px-4 rounded-2xl shadow-md flex items-center justify-center gap-2 transition">
                        <svg class="w-4 h-4 fill-white shrink-0" viewBox="0 0 24 24"><path d="M.057 24l1.687-6.163c-1.041-1.804-1.588-3.849-1.587-5.946.003-6.556 5.338-11.891 11.893-11.891 3.181.001 6.167 1.24 8.413 3.488 2.245 2.248 3.481 5.236 3.48 8.414-.003 6.557-5.338 11.892-11.893 11.892-1.99-.001-3.951-.5-5.688-1.448l-6.305 1.654zm6.597-3.807c1.676.995 3.276 1.591 5.392 1.592 5.448 0 9.886-4.434 9.889-9.885.002-5.462-4.415-9.89-9.881-9.892-5.452 0-9.887 4.434-9.889 9.884-.001 2.225.651 3.891 1.746 5.634l-.999 3.648 3.742-.981zm11.387-5.464c-.074-.124-.272-.198-.57-.347-.297-.149-1.758-.868-2.031-.967-.272-.099-.47-.149-.669.149-.198.297-.768.967-.941 1.165-.173.198-.347.223-.644.074-.297-.149-1.255-.462-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.297-.347.446-.521.151-.172.2-.296.3-.495.099-.198.05-.372-.025-.521-.075-.148-.669-1.611-.916-2.206-.242-.579-.487-.501-.669-.51l-.57-.01c-.198 0-.52.074-.792.372s-1.04 1.016-1.04 2.479 1.065 2.876 1.213 3.074c.149.198 2.095 3.2 5.076 4.487.709.306 1.263.489 1.694.626.712.226 1.36.194 1.872.118.571-.085 1.758-.719 2.006-1.413.248-.695.248-1.29.173-1.414z"/></svg>
                        <span>اطلب عمل مماثل</span>
                    </a>
                    {download_btn}
                </div>
                {admin_work_bar}
            </div>
        </div>''')

    conn.close()

    # تم إزالة أزرار الأدمن من الواجهة هنا
    admin_quick_works_btn = ''
    admin_quick_courses_btn = ''

    content = f'''
    <div class="max-w-7xl mx-auto px-4 sm:px-6 py-8 space-y-14">
        
        <!-- 🏆 البوكس الترحيبي الإبداعي في جهة اليمين (Right-Aligned Creative Hero Box) -->
        <div class="w-full flex justify-start">
            <div class="w-full lg:w-3/4 xl:w-2/3 relative overflow-hidden bg-gradient-to-l from-[#064E3B] via-[#0F766E] to-[#1E3A8A] rounded-[24px] sm:rounded-[32px] p-5 sm:p-9 text-white shadow-2xl border-r-4 sm:border-r-8 border-amber-400">
                <!-- تأثيرات ضوئية خلفية إبداعية -->
                <div class="absolute -top-16 -right-16 w-56 h-56 bg-amber-400/20 rounded-full blur-3xl pointer-events-none"></div>
                <div class="absolute -bottom-20 left-10 w-64 h-64 bg-teal-300/20 rounded-full blur-3xl pointer-events-none"></div>
                
                <div class="relative z-10 text-right space-y-3 sm:space-y-4">
                    <div class="flex items-center justify-start gap-2 flex-wrap">
                        <span class="bg-gradient-to-r from-amber-300 to-amber-500 text-slate-950 font-black text-[11px] sm:text-xs px-3.5 py-1 rounded-full shadow-md">
                            {hero_badge_1}
                        </span>
                        <span class="bg-white/15 backdrop-blur-md text-amber-200 text-[11px] sm:text-xs font-black px-3.5 py-1 rounded-full border border-white/25">
                            ✨ {hero_badge_2}
                        </span>
                    </div>

                    <h1 class="text-xl sm:text-3xl md:text-4xl font-black text-white leading-snug">
                        {hero_title}
                    </h1>
                    
                    <p class="text-xs sm:text-sm text-emerald-50/95 font-bold leading-relaxed max-w-2xl">
                        {hero_desc}
                    </p>

                    <div class="pt-2 sm:pt-3 flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center justify-start gap-2.5">
                        <a href="https://wa.me/{wa_num}" target="_blank" class="bg-amber-400 hover:bg-amber-300 text-slate-950 flex items-center justify-center gap-2 px-5 py-3 rounded-2xl font-black text-xs sm:text-sm shadow-lg transition">
                            <svg class="w-4 h-4 sm:w-5 sm:h-5 fill-slate-950 shrink-0" viewBox="0 0 24 24"><path d="M.057 24l1.687-6.163c-1.041-1.804-1.588-3.849-1.587-5.946.003-6.556 5.338-11.891 11.893-11.891 3.181.001 6.167 1.24 8.413 3.488 2.245 2.248 3.481 5.236 3.48 8.414-.003 6.557-5.338 11.892-11.893 11.892-1.99-.001-3.951-.5-5.688-1.448l-6.305 1.654zm6.597-3.807c1.676.995 3.276 1.591 5.392 1.592 5.448 0 9.886-4.434 9.889-9.885.002-5.462-4.415-9.89-9.881-9.892-5.452 0-9.887 4.434-9.889 9.884-.001 2.225.651 3.891 1.746 5.634l-.999 3.648 3.742-.981zm11.387-5.464c-.074-.124-.272-.198-.57-.347-.297-.149-1.758-.868-2.031-.967-.272-.099-.47-.149-.669.149-.198.297-.768.967-.941 1.165-.173.198-.347.223-.644.074-.297-.149-1.255-.462-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.297-.347.446-.521.151-.172.2-.296.3-.495.099-.198.05-.372-.025-.521-.075-.148-.669-1.611-.916-2.206-.242-.579-.487-.501-.669-.51l-.57-.01c-.198 0-.52.074-.792.372s-1.04 1.016-1.04 2.479 1.065 2.876 1.213 3.074c.149.198 2.095 3.2 5.076 4.487.709.306 1.263.489 1.694.626.712.226 1.36.194 1.872.118.571-.085 1.758-.719 2.006-1.413.248-.695.248-1.29.173-1.414z"/></svg>
                            <span>طلب عمل خاص / تواصل واتساب</span>
                        </a>
                        <a href="#works" class="bg-white/15 hover:bg-white/25 backdrop-blur-md text-white border border-white/30 px-5 py-3 rounded-2xl text-center text-xs sm:text-sm font-black transition">
                            تصفح الأعمال الاحترافية &lsaquo;
                        </a>
                        <a href="#courses" class="bg-white/10 hover:bg-white/20 backdrop-blur-md text-amber-200 border border-amber-300/30 px-5 py-3 rounded-2xl text-center text-xs sm:text-sm font-black transition">
                            استعراض المقررات &lsaquo;
                        </a>
                    </div>
                </div>
            </div>
        </div>

        <!-- 📝 قسم الأعمال والمشاريع الاحترافية المميزة -->
        <div id="works" class="space-y-6">
            <div class="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-slate-200 pb-4">
                <div>
                    <span class="text-xs font-black text-teal-600 bg-teal-50 px-3 py-1 rounded-full border border-teal-200 inline-block mb-2">✨ معرض التميز الأكاديمي</span>
                    <h2 class="text-xl sm:text-3xl font-black text-slate-900 flex items-center gap-2">
                        <span>الأعمال والمشاريع الاحترافية المميزة</span>
                    </h2>
                    <p class="text-xs sm:text-sm text-slate-500 font-bold mt-1">نماذج احترافية من مشاريع التخرج، البحوث، حلول الواجبات، والتقارير الهندسية والبرمجية</p>
                </div>
                <div class="flex items-center gap-2 flex-wrap">
                    {admin_quick_works_btn}
                    <a href="/semester-works" class="text-xs font-black text-white bg-teal-600 hover:bg-teal-700 px-5 py-2.5 rounded-2xl shadow-xs transition">
                        عرض صفحة جميع الأعمال ({len(works)}) &lsaquo;
                    </a>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 sm:gap-7">
                {''.join(featured_works_cards) if featured_works_cards else '<p class="text-center text-xs text-slate-400 py-8 col-span-3">لا توجد أعمال مضافة حالياً</p>'}
            </div>
        </div>

        <!-- 📚 قسم المقررات والملخصات (تصميم إبداعي جديد) -->
        <div id="courses" class="space-y-6 pt-4">
            <div class="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-slate-200 pb-4">
                <div>
                    <span class="text-xs font-black text-indigo-600 bg-indigo-50 px-3 py-1 rounded-full border border-indigo-200 inline-block mb-2">🎓 شروحات وملازم جامعية</span>
                    <h2 class="text-xl sm:text-3xl font-black text-slate-900">أبرز المقررات والملخصات المعتمدة</h2>
                    <p class="text-xs sm:text-sm text-slate-500 font-bold mt-1">شروحات فيديو مفصلة، ملازم مراجعة، وتجميعات اختبارات (ميد + فاينل) لضمان أعلى الدرجات</p>
                </div>
                <div class="flex items-center gap-2">
                    {admin_quick_courses_btn}
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 sm:gap-7">
                {''.join(course_cards) if course_cards else '<p class="text-center text-xs text-slate-400 py-8 col-span-3">لا توجد مواد مضافة بعد</p>'}
            </div>
        </div>

        <!-- 🏛️ الجامعات المعتمدة -->
        <div id="unis" class="space-y-6 pt-6">
            <div class="text-center space-y-1 max-w-xl mx-auto">
                <span class="text-xs font-black text-amber-700 bg-amber-100 px-3.5 py-1 rounded-full inline-block mb-1">🏛️ الجامعات السعودية</span>
                <h2 class="text-xl sm:text-2xl font-black text-slate-900">الجامعات المعتمدة بالمنصة</h2>
                <p class="text-xs font-bold text-slate-400">اختر جامعتك لتصفح جميع الشروحات والمواد الخاصة بها</p>
            </div>
            <div class="grid grid-cols-2 sm:grid-cols-2 md:grid-cols-4 gap-4 sm:gap-5 pt-8">
                {''.join(uni_cards)}
            </div>
        </div>

    </div>
    '''
    return render_template('base.html', content=content)


@app.route('/semester-works')
def semester_works():
    conn = get_db()
    settings = get_site_settings(conn)
    wa_num = settings.get('whatsapp_number', '966593521664')
    works = conn.execute('SELECT * FROM semester_works ORDER BY id DESC').fetchall()
    conn.close()
    is_admin = is_admin_authenticated()

    cards = []
    for idx, w in enumerate(works):
        file_btn = f'<a href="/uploads/{w["file_name"]}" target="_blank" class="bg-slate-100 hover:bg-teal-50 text-slate-800 hover:text-teal-700 border border-slate-200 text-xs font-black px-4 py-2.5 rounded-2xl transition">تحميل المرفق 📥</a>' if w['file_name'] else ''
        wa_work_msg = f"مرحباً، أود الطلب والاستفسار عن العمل الفصلي ({w['title']}) باسم الطالب عبر منصة إتقان."
        wa_work_link = f"https://wa.me/{wa_num}?text={wa_work_msg}"

        if w['cover_img']:
            img_url = w['cover_img'] if w['cover_img'].startswith('http') else f'/uploads/{w["cover_img"]}'
            cover_tag = f'<img src="{img_url}" class="w-full h-52 object-cover group-hover:scale-110 transition-transform duration-500">'
        else:
            cover_tag = '''
            <div class="w-full h-52 bg-gradient-to-br from-teal-600 via-emerald-600 to-sky-700 flex flex-col items-center justify-center text-white p-6">
                <div class="w-16 h-16 rounded-2xl bg-white/15 flex items-center justify-center text-3xl mb-2">🚀</div>
                <span class="text-xs font-black text-teal-100">مشروع أكاديمي معتمد</span>
            </div>'''

        # تم إزالة أزرار الأدمن
        admin_bar = ''

        cards.append(f'''
        <div class="group bg-white rounded-[28px] border border-slate-200/80 shadow-sm hover:shadow-xl transition-all duration-300 flex flex-col justify-between overflow-hidden">
            <div>
                <div class="relative overflow-hidden h-52">
                    {cover_tag}
                    <div class="absolute inset-0 bg-gradient-to-t from-slate-950/80 via-transparent to-transparent"></div>
                    <span class="absolute top-3.5 right-3.5 bg-amber-400 text-slate-950 text-[11px] font-black px-3.5 py-1 rounded-full shadow-sm">{w['faculty']}</span>
                </div>
                <div class="p-5">
                    <h3 class="font-black text-lg text-slate-900 mb-2">{w['title']}</h3>
                    <p class="text-xs text-slate-500 leading-relaxed mb-4">{w['desc']}</p>
                </div>
            </div>
            <div>
                <div class="px-5 pb-5 pt-3 border-t border-slate-100 flex items-center justify-between gap-2">
                    <a href="{wa_work_link}" target="_blank" class="flex-grow bg-gradient-to-l from-emerald-600 to-teal-500 text-white text-xs font-black py-2.5 px-4 rounded-2xl flex items-center justify-center gap-1.5 shadow-sm">
                        <span>طلب عبر الواتساب</span>
                    </a>
                    {file_btn}
                </div>
                {admin_bar}
            </div>
        </div>''')

    content = f'''
    <div class="max-w-7xl mx-auto px-4 sm:px-6 py-10">
        <div class="text-center mb-10 space-y-2">
            <span class="text-3xl">📝</span>
            <h1 class="text-2xl sm:text-3xl font-black text-slate-900">الأعمال والمشاريع الاحترافية المميزة</h1>
            <p class="text-xs sm:text-sm text-slate-500 max-w-lg mx-auto">تصفح التكاليف والأنشطة، مشاريع التخرج، والملخصات الفصلية المعتمدة لجميع التخصصات.</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-7">
            {''.join(cards) if cards else '<div class="bg-slate-50 p-8 rounded-3xl text-center text-xs text-slate-400 col-span-3">لا توجد أعمال فصلية منشورة حالياً</div>'}
        </div>
    </div>
    '''
    return render_template('base.html', content=content)


@app.route('/uni/<int:uni_id>')
def uni_detail(uni_id):
    conn = get_db()
    uni = conn.execute('SELECT * FROM universities WHERE id=?', (uni_id,)).fetchone()
    if not uni:
        conn.close()
        return redirect('/')
    courses = conn.execute('''
        SELECT c.*, (SELECT COUNT(*) FROM lessons l WHERE l.course_id = c.id) as lesson_count
        FROM courses c WHERE uni_id=?
    ''', (uni_id,)).fetchall()

    cards = []
    for c in courses:
        cover_tag = f'<img src="/uploads/{c["cover_img"]}" class="w-full h-48 object-cover">' if c['cover_img'] else '<div class="w-full h-48 bg-gradient-to-br from-indigo-600 to-cyan-500 flex items-center justify-center text-4xl text-white">📚</div>'

        # تم إزالة أزرار الأدمن
        admin_bar = ''

        cards.append(f'''
        <div class="bg-white rounded-[28px] border border-slate-200 shadow-sm hover:shadow-xl transition flex flex-col justify-between overflow-hidden">
            <div>
                <div class="relative h-48 overflow-hidden">
                    {cover_tag}
                    <span class="absolute top-3 left-3 bg-slate-900/80 text-amber-300 text-[11px] font-mono font-black px-3 py-1 rounded-full">{c['code'] or 'COURSE'}</span>
                </div>
                <div class="p-5">
                    <h4 class="font-black text-base text-slate-900 mb-1">{c['title']}</h4>
                    <p class="text-xs text-slate-500 line-clamp-2 mb-4">{c['desc']}</p>
                </div>
            </div>
            <div>
                <div class="px-5 pb-5 pt-3 border-t border-slate-100 flex items-center justify-between">
                    <span class="font-black text-lg text-slate-900">{c['price']:g} <span class="text-xs font-bold text-teal-600">ر.س</span></span>
                    <a href="/course/{c['id']}" class="bg-slate-900 hover:bg-teal-500 text-white hover:text-slate-950 text-xs font-black px-5 py-2.5 rounded-2xl transition">تصفح المقرر &lsaquo;</a>
                </div>
                {admin_bar}
            </div>
        </div>''')
    conn.close()

    logo_img = uni['logo_img'] if 'logo_img' in uni.keys() else None
    logo_tag = f'<img src="/uploads/{logo_img}" class="w-14 h-14 object-contain rounded-2xl">' if logo_img else f'<div class="text-4xl">{uni["logo"] or "🏛️"}</div>'

    content = f'''
    <div class="max-w-7xl mx-auto px-4 sm:px-6 py-8">
        <div class="bg-white rounded-[32px] p-6 border border-slate-200 shadow-xs mb-8 flex items-center gap-4">
            <div class="w-16 h-16 bg-slate-50 rounded-2xl shadow-xs flex items-center justify-center">{logo_tag}</div>
            <div>
                <h1 class="text-xl font-black text-slate-900">{uni["name"]}</h1>
                <p class="text-xs text-slate-500 mt-1">{uni["desc"] or "مقررات وشروحات الجامعة"}</p>
            </div>
        </div>

        <h2 class="text-xl font-black text-slate-900 mb-5">المواد المتاحة في الجامعة ({len(cards)})</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-7">
            {''.join(cards) if cards else '<div class="text-center py-12 text-slate-400 text-xs col-span-3">لا توجد مواد مضافة لهذه الجامعة حالياً</div>'}
        </div>
    </div>
    '''
    return render_template('base.html', content=content)


@app.route('/course/<int:course_id>')
def course_detail(course_id):
    conn = get_db()
    settings = get_site_settings(conn)
    wa_num = settings.get('whatsapp_number', '966593521664')
    academy_name = settings.get('academy_name', 'أكاديمية إتقان التعليمية')
    academy_bio = settings.get('academy_bio', 'نخبة من الأكاديميين والمحاضرين المتخصصين في تبسيط وشرح المقررات الجامعية وتلخيصها ومتابعة الطلاب لتحقيق الامتياز A+.')
    students_count = settings.get('students_count', '+1000')
    academy_rating = settings.get('academy_rating', '5.0')
    legal_warning = settings.get('legal_warning', 'تحذير قانوني : لا يجوز نشره أو مشاركته')

    c = conn.execute('''
        SELECT c.*, u.name as uname 
        FROM courses c 
        LEFT JOIN universities u ON c.uni_id=u.id 
        WHERE c.id=?
    ''', (course_id,)).fetchone()
    if not c:
        conn.close()
        return redirect('/')

    lessons = conn.execute('SELECT * FROM lessons WHERE course_id=? ORDER BY id ASC', (course_id,)).fetchall()
    uid = session.get('user_id')

    enrolled = False
    if uid:
        row = conn.execute('SELECT status FROM enrollments WHERE user_id=? AND course_id=?', (uid, course_id)).fetchone()
        if row and row['status'] == 'approved':
            enrolled = True

    admin_logged = is_admin_authenticated()

    lesson_items = []
    for idx, l in enumerate(lessons, 1):
        is_first_lesson = (idx == 1)
        can_access = is_first_lesson or enrolled or admin_logged

        has_video = ('video_filename' in l.keys() and l['video_filename'])
        has_pdf = ('pdf_filename' in l.keys() and l['pdf_filename'])

        btn_video = f'<a href="/watch/{l["id"]}" class="bravo-teal-btn text-[11px] font-black px-3.5 py-1.5 rounded-full text-slate-900">الشرح ▶</a>' if (has_video and can_access) else ('<span class="text-[11px] text-slate-400 font-bold bg-slate-100 px-2.5 py-1.5 rounded-full border border-slate-200">🔒 مقفل</span>' if has_video else '')
        btn_pdf = f'<a href="/stream_pdf/{l["pdf_filename"]}" target="_blank" class="bg-blue-50 text-blue-700 border border-blue-200 text-[11px] font-black px-3 py-1.5 rounded-full hover:bg-blue-100">الملخص 📄</a>' if (has_pdf and can_access) else ('<span class="text-[11px] text-slate-400 font-bold bg-slate-100 px-2.5 py-1.5 rounded-full border border-slate-200">🔒 ملخص</span>' if has_pdf else '')
        preview_badge = '<span class="text-[10px] bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded-md font-black mr-2">تجريبي مجاناً</span>' if is_first_lesson else ''

        lesson_items.append(f'''
        <div class="p-3.5 flex items-center justify-between hover:bg-slate-50 transition">
            <div class="flex items-center gap-2">
                <span class="w-6 h-6 rounded-full bg-slate-100 text-slate-800 text-xs font-black flex items-center justify-center">{idx}</span>
                <span class="text-xs font-bold text-slate-800">{l["title"]}</span>
                {preview_badge}
            </div>
            <div class="flex items-center gap-1.5">
                {btn_pdf}
                {btn_video}
            </div>
        </div>''')

    conn.close()

    cover_tag = f'<img src="/uploads/{c["cover_img"]}" class="w-full h-56 object-cover rounded-[32px]">' if c['cover_img'] else '<div class="w-full h-56 bg-gradient-to-b from-[#38bdf8] to-[#60a5fa] rounded-[32px] flex items-center justify-center text-5xl">🎯</div>'

    code_val = c['code'] if 'code' in c.keys() else ''
    faculty_val = c['faculty'] if 'faculty' in c.keys() else 'كلية الهندسة'
    target_val = c['target_audience'] if 'target_audience' in c.keys() else 'طلاب وطالبات'
    old_p = c['old_price'] if 'old_price' in c.keys() else 0
    mid_p = c['mid_price'] if 'mid_price' in c.keys() else 100
    mid_old = c['mid_old_price'] if 'mid_old_price' in c.keys() else 150
    fin_p = c['final_price'] if 'final_price' in c.keys() else 120
    fin_old = c['final_old_price'] if 'final_old_price' in c.keys() else 170

    course_js = """
    <script>
        function switchTab(num) {
            for (var i = 1; i <= 4; i++) {
                document.getElementById('tab-content-' + i).classList.add('hidden');
                document.getElementById('tab-btn-' + i).className = 'bg-[#F4F6F8] text-slate-700 py-2.5 rounded-2xl transition';
            }
            document.getElementById('tab-content-' + num).classList.remove('hidden');
            document.getElementById('tab-btn-' + num).className = 'bg-[#1E293B] text-white py-2.5 rounded-2xl transition shadow-xs';
        }

        function togglePackageModal() {
            document.getElementById('package-modal').classList.toggle('hidden');
        }

        function selectPackage(type, price, oldPrice, label) {
            document.getElementById('display-price').innerText = price;
            document.getElementById('display-old-price').innerText = oldPrice > 0 ? oldPrice : '';
            document.getElementById('selected-package-label').innerText = label;
            togglePackageModal();
        }
    </script>
    """

    content = f'''
    <div class="max-w-md md:max-w-3xl mx-auto px-4 py-4 pb-28">
        <div class="flex items-center gap-1.5 text-[11px] font-bold text-slate-400 mb-3">
            <a href="/" class="hover:underline">الرئيسية</a>
            <span>&rsaquo;</span>
            <span class="text-slate-600">{c['uname'] or 'جامعة الملك خالد'}</span>
        </div>

        <div class="mb-4">{cover_tag}</div>

        <div class="flex items-center justify-between mb-2">
            <h1 class="text-xl font-black text-slate-900">{c['title']} {code_val}</h1>
            <div class="flex items-center gap-1 text-xs font-bold text-slate-700">
                <span>{academy_rating}</span>
                <span class="text-amber-400">★</span>
            </div>
        </div>

        <div class="bg-rose-50 border border-rose-100 rounded-2xl p-2.5 text-center text-[11px] font-bold text-rose-600 mb-4">
            {legal_warning}
        </div>

        <div class="flex items-center gap-2 mb-4 flex-wrap">
            <span class="bg-[#F8CD46] text-slate-900 text-xs font-black px-4 py-1 rounded-full">{c['uname'] or 'جامعة الملك خالد'}</span>
            <span class="bg-[#4AD7C5] text-slate-900 text-xs font-black px-4 py-1 rounded-full">{faculty_val}</span>
            <span class="bg-[#8B5CF6] text-white text-xs font-black px-4 py-1 rounded-full">{target_val}</span>
        </div>

        <div class="flex items-center justify-between mb-4">
            <div class="text-2xl font-black text-slate-900">
                <span id="display-price">{c['price']:g}</span> <span class="text-sm font-bold text-slate-500">ر.س</span>
                <span id="display-old-price" class="text-slate-400 line-through text-sm font-bold mr-1">{f"{old_p:g}" if old_p and old_p > 0 else ''}</span>
            </div>
            
            <button onclick="togglePackageModal()" class="bg-white border border-slate-200 rounded-2xl px-4 py-2 text-xs font-bold text-slate-700 flex items-center gap-2 shadow-xs">
                <span id="selected-package-label">المنهج كامل</span>
                <span class="text-[10px] text-slate-400">▼</span>
            </button>
        </div>

        <div class="space-y-3 mb-6">
            <a href="/checkout/{c['id']}" class="bravo-teal-btn w-full block text-center py-3 rounded-full font-black text-slate-900 text-xs">الاشتراك في المقرر &lsaquo;</a>
        </div>

        <div class="grid grid-cols-4 gap-1.5 mb-6 text-center text-xs font-black">
            <button id="tab-btn-1" onclick="switchTab(1)" class="bg-[#1E293B] text-white py-2.5 rounded-2xl transition shadow-xs">محتوى المنهج</button>
            <button id="tab-btn-2" onclick="switchTab(2)" class="bg-[#F4F6F8] text-slate-700 py-2.5 rounded-2xl transition">تفاصيل المقرر</button>
            <button id="tab-btn-3" onclick="switchTab(3)" class="bg-[#F4F6F8] text-slate-700 py-2.5 rounded-2xl transition">الجهة الشارحة</button>
            <button id="tab-btn-4" onclick="switchTab(4)" class="bg-[#F4F6F8] text-slate-700 py-2.5 rounded-2xl transition">التقييمات</button>
        </div>

        <div id="tab-content-1" class="space-y-4">
            <div class="bg-white rounded-3xl border border-slate-100 shadow-xs overflow-hidden">
                <div class="p-4 bg-slate-50 border-b border-slate-100 flex items-center justify-between">
                    <span class="font-black text-xs text-slate-800">قائمة الشروحات والملخصات المرفقة</span>
                    <span class="text-xs font-bold text-slate-400">{len(lessons)} درس</span>
                </div>
                <div class="divide-y divide-slate-100">
                    {''.join(lesson_items) if lesson_items else '<p class="p-6 text-xs text-slate-400 text-center">لا توجد دروس مرفوعة بعد</p>'}
                </div>
            </div>
        </div>

        <div id="tab-content-2" class="hidden space-y-4">
            <div class="bg-white rounded-3xl p-5 border border-slate-100 shadow-xs">
                <h3 class="font-black text-sm text-slate-900 mb-2">📖 وصف وتفاصيل المقرر:</h3>
                <p class="text-xs text-slate-600 leading-relaxed">{c['desc']}</p>
            </div>
        </div>

        <div id="tab-content-3" class="hidden space-y-4">
            <div class="bg-white rounded-3xl p-6 border border-slate-100 shadow-xs text-center">
                <div class="w-14 h-14 rounded-full bg-[#0B4B80] text-white flex items-center justify-center font-black text-xl mx-auto mb-3">إ</div>
                <h2 class="text-lg font-black text-slate-900 mb-1">{academy_name}</h2>
                <div class="flex justify-center gap-4 text-xs font-bold text-slate-500 mb-4">
                    <span>👥 {students_count} طالب وطالبة</span>
                    <span>📚 أعلى جودة تعليمية</span>
                </div>
                <p class="text-xs text-slate-600 leading-relaxed mb-4">{academy_bio}</p>
                <a href="/instructor/1" class="bravo-teal-btn inline-block px-8 py-2.5 rounded-full text-xs font-black text-slate-900">الملف الأكاديمي &lsaquo;</a>
            </div>
        </div>

        <div id="tab-content-4" class="hidden space-y-4">
            <div class="bg-white rounded-3xl p-6 border border-slate-100 shadow-xs text-center">
                <span class="text-4xl font-black text-slate-900 block mb-1">{academy_rating}</span>
                <div class="flex justify-center text-amber-400 text-lg mb-2">★★★★★</div>
                <span class="text-xs text-slate-400 font-bold block mb-4">تقييم الطلاب المعتمد</span>
            </div>
        </div>
    </div>

    <div id="package-modal" class="fixed inset-0 z-50 flex items-end justify-center hidden">
        <div class="fixed inset-0 bg-slate-900/40 backdrop-blur-xs" onclick="togglePackageModal()"></div>
        <div class="relative bg-white w-full max-w-md rounded-t-[36px] p-6 z-10 shadow-2xl space-y-4">
            <div class="w-12 h-1 bg-slate-200 rounded-full mx-auto mb-2"></div>
            <h3 class="text-center font-black text-sm text-slate-800 mb-4">اختر باقة المقرر</h3>
            
            <div onclick="selectPackage('full', {c['price'] or 0}, {old_p or 0}, 'المنهج كامل')" class="flex items-center justify-between p-4 rounded-2xl border-2 border-teal-400 bg-teal-50/50 cursor-pointer">
                <span class="font-black text-xs text-slate-800">المنهج كامل</span>
                <span class="font-black text-sm text-slate-900">{c['price']:g} ر.س</span>
            </div>

            <div onclick="selectPackage('mid', {mid_p or 0}, {mid_old or 0}, 'الميد')" class="flex items-center justify-between p-4 rounded-2xl border border-slate-200 hover:border-slate-800 transition cursor-pointer">
                <span class="font-black text-xs text-slate-800">الميد</span>
                <span class="font-black text-sm text-slate-900">{mid_p:g} ر.س</span>
            </div>

            <div onclick="selectPackage('final', {fin_p or 0}, {fin_old or 0}, 'الفاينل')" class="flex items-center justify-between p-4 rounded-2xl border border-slate-200 hover:border-slate-800 transition cursor-pointer">
                <span class="font-black text-xs text-slate-800">الفاينل</span>
                <span class="font-black text-sm text-slate-900">{fin_p:g} ر.س</span>
            </div>
        </div>
    </div>

    <div class="fixed bottom-0 left-0 right-0 bg-white/95 backdrop-blur-md border-t border-slate-100 p-3 z-40">
        <div class="max-w-md mx-auto flex items-center justify-between gap-3">
            <a href="/checkout/{c['id']}" class="bravo-teal-btn flex-grow py-3 rounded-full text-center text-slate-900 font-black text-xs shadow-md">
                الاشتراك في المقرر &lsaquo;
            </a>
            <div class="bg-slate-100 px-3.5 py-2 rounded-2xl text-[11px] font-bold text-slate-600 whitespace-nowrap">
                📖 {len(lessons)} درس
            </div>
            <a href="https://wa.me/{wa_num}" target="_blank" title="تواصل واتساب" class="w-10 h-10 bg-[#25D366] border-2 border-slate-900 rounded-full flex items-center justify-center shrink-0 shadow-xs hover:scale-105 transition">
                <svg class="w-5 h-5 fill-white" viewBox="0 0 24 24"><path d="M.057 24l1.687-6.163c-1.041-1.804-1.588-3.849-1.587-5.946.003-6.556 5.338-11.891 11.893-11.891 3.181.001 6.167 1.24 8.413 3.488 2.245 2.248 3.481 5.236 3.48 8.414-.003 6.557-5.338 11.892-11.893 11.892-1.99-.001-3.951-.5-5.688-1.448l-6.305 1.654zm6.597-3.807c1.676.995 3.276 1.591 5.392 1.592 5.448 0 9.886-4.434 9.889-9.885.002-5.462-4.415-9.89-9.881-9.892-5.452 0-9.887 4.434-9.889 9.884-.001 2.225.651 3.891 1.746 5.634l-.999 3.648 3.742-.981zm11.387-5.464c-.074-.124-.272-.198-.57-.347-.297-.149-1.758-.868-2.031-.967-.272-.099-.47-.149-.669.149-.198.297-.768.967-.941 1.165-.173.198-.347.223-.644.074-.297-.149-1.255-.462-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.297-.347.446-.521.151-.172.2-.296.3-.495.099-.198.05-.372-.025-.521-.075-.148-.669-1.611-.916-2.206-.242-.579-.487-.501-.669-.51l-.57-.01c-.198 0-.52.074-.792.372s-1.04 1.016-1.04 2.479 1.065 2.876 1.213 3.074c.149.198 2.095 3.2 5.076 4.487.709.306 1.263.489 1.694.626.712.226 1.36.194 1.872.118.571-.085 1.758-.719 2.006-1.413.248-.695.248-1.29.173-1.414z"/></svg>
            </a>
        </div>
    </div>
    ''' + course_js
    return render_template('base.html', content=content)


@app.route('/watch/<int:lesson_id>')
def watch_lesson(lesson_id):
    conn = get_db()
    l = conn.execute('SELECT l.*, c.title as cname FROM lessons l LEFT JOIN courses c ON l.course_id=c.id WHERE l.id=?', (lesson_id,)).fetchone()
    if not l:
        conn.close()
        return redirect('/')
    all_lessons = conn.execute('SELECT id FROM lessons WHERE course_id=? ORDER BY id ASC', (l['course_id'],)).fetchall()
    is_first = (all_lessons and all_lessons[0]['id'] == lesson_id)
    uid = session.get('user_id')
    enrolled = False
    if uid:
        row = conn.execute('SELECT status FROM enrollments WHERE user_id=? AND course_id=?', (uid, l['course_id'])).fetchone()
        if row and row['status'] == 'approved':
            enrolled = True
    conn.close()

    if not (is_first or enrolled or is_admin_authenticated()):
        return redirect(f"/checkout/{l['course_id']}")

    # تم التعديل هنا لاستخدام دالة البث المباشر /stream_video
    vid_html = f'''
    <video controls controlsList="nodownload" oncontextmenu="return false;" class="w-full rounded-3xl bg-slate-950 shadow-xl border border-slate-800 max-h-[500px]">
        <source src="/stream_video/{l['video_filename']}" type="video/mp4">
        متصفحك لا يدعم تشغيل الفيديو.
    </video>''' if l['video_filename'] else '<div class="p-12 text-center bg-slate-100 rounded-3xl text-xs font-bold text-slate-500">لا يوجد فيديو مرفق لهذا الدرس</div>'

    # تم التعديل هنا لاستخدام دالة البث المباشر /stream_pdf
    pdf_btn = f'''
    <a href="/stream_pdf/{l['pdf_filename']}" target="_blank" class="bravo-teal-btn inline-flex items-center gap-2 px-6 py-3 rounded-full text-xs font-black text-slate-900">
        <span>📄 عرض الملف المرفق (PDF)</span>
    </a>''' if l['pdf_filename'] else ''

    content = f'''
    <div class="max-w-3xl mx-auto px-4 py-8 space-y-6">
        <div class="flex items-center justify-between">
            <div>
                <span class="text-xs font-bold text-teal-600">{l['cname'] or ''}</span>
                <h1 class="text-xl font-black text-slate-900 mt-0.5">{l['title']}</h1>
            </div>
            <a href="/course/{l['course_id']}" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-full text-xs font-black">العودة للمادة &lsaquo;</a>
        </div>
        {vid_html}
        <div class="flex justify-center">{pdf_btn}</div>
    </div>'''
    return render_template('base.html', content=content)


@app.route('/instructor/<int:inst_id>')
def instructor_detail(inst_id):
    conn = get_db()
    settings = get_site_settings(conn)
    inst = conn.execute('SELECT * FROM instructors WHERE id=?', (inst_id,)).fetchone()
    courses = conn.execute('''
        SELECT c.*, u.name as uname 
        FROM courses c 
        LEFT JOIN universities u ON c.uni_id=u.id 
        WHERE c.instructor_id=?
    ''', (inst_id,)).fetchall()
    conn.close()

    cards = []
    for c in courses:
        cover_img = c['cover_img'] if 'cover_img' in c.keys() else None
        cover_tag = f'<img src="/uploads/{cover_img}" class="w-full h-44 object-cover rounded-[28px] mb-2">' if cover_img else '<div class="w-full h-44 bg-[#0B4B80] rounded-[28px] mb-2 flex items-center justify-center text-3xl font-black text-white/40">🎯</div>'
        cards.append(f'''
        <a href="/course/{c['id']}" class="bg-white p-3 rounded-[32px] border border-slate-100 shadow-xs block">
            <div class="relative">
                {cover_tag}
                <div class="absolute bottom-4 right-3 bg-white/95 backdrop-blur-md px-3 py-1 rounded-xl text-[11px] font-bold text-slate-800 shadow-xs flex items-center gap-1">
                    <span class="text-amber-400">★ {settings.get('academy_rating', '5.0')}</span>
                    <span>{c['title']}</span>
                </div>
            </div>
            <div class="flex justify-between items-center px-2 pt-1 text-xs">
                <span class="font-black text-slate-900">{c['price']:g} ر.س</span>
                <span class="text-teal-600 font-bold">عرض المقرر &lsaquo;</span>
            </div>
        </a>''')

    avatar_tag = f'<img src="/uploads/{inst["avatar_img"]}" class="w-20 h-20 rounded-full object-cover border-4 border-white shadow-md">' if (inst and 'avatar_img' in inst.keys() and inst['avatar_img']) else '<div class="w-20 h-20 rounded-full bg-[#0B4B80] text-white flex items-center justify-center text-2xl font-black border-4 border-white shadow-md">إ</div>'
    inst_name = inst['name'] if inst else settings.get('academy_name', 'أكاديمية إتقان التعليمية')
    inst_bio = inst['bio'] if inst else settings.get('academy_bio', '')

    content = f'''
    <div class="max-w-md mx-auto px-4 py-4 pb-20">
        <div class="relative bg-gradient-to-r from-slate-900 to-[#0B4B80] h-32 rounded-[32px] shadow-sm mb-12">
            <div class="absolute -bottom-8 left-1/2 -translate-x-1/2">{avatar_tag}</div>
        </div>

        <div class="text-center mb-6">
            <h1 class="text-xl font-black text-slate-900 mb-1">{inst_name}</h1>
            <div class="flex justify-center text-amber-400 text-sm mb-1">★★★★★ <span class="text-slate-400 text-xs font-bold mr-1">(تقييم {settings.get('academy_rating', '5.0')})</span></div>
            
            <div class="flex justify-center gap-6 text-center my-4">
                <div><span class="text-lg font-black text-slate-900 block">{len(courses)}</span><span class="text-[11px] text-slate-400 font-bold">مادة</span></div>
                <div class="border-r border-slate-200"></div>
                <div><span class="text-lg font-black text-slate-900 block">{settings.get('students_count', '+1000')}</span><span class="text-[11px] text-slate-400 font-bold">طالب مشترك</span></div>
            </div>
        </div>

        <div class="bg-white rounded-3xl p-5 border border-slate-100 shadow-xs mb-6">
            <h3 class="font-black text-sm text-slate-900 mb-2">نبذة عن الأكاديمية</h3>
            <p class="text-xs text-slate-600 leading-relaxed mb-4">{inst_bio}</p>
        </div>

        <h3 class="font-black text-sm text-slate-900 mb-3">المواد والشروحات المقدمة ({len(courses)})</h3>
        <div class="space-y-4">
            {''.join(cards) if cards else '<p class="text-center text-xs text-slate-400 py-6">لا توجد مواد مضافة بعد</p>'}
        </div>
    </div>
    '''
    return render_template('base.html', content=content)


@app.route('/checkout/<int:course_id>')
def checkout(course_id):
    if not session.get('user_id'):
        return redirect(f'/login?next=/checkout/{course_id}')

    conn = get_db()
    settings = get_site_settings(conn)
    wa_num = settings.get('whatsapp_number', '966593521664')
    c = conn.execute('SELECT * FROM courses WHERE id=?', (course_id,)).fetchone()
    if not c:
        conn.close()
        return redirect('/')
    banks = conn.execute('SELECT * FROM bank_accounts').fetchall()
    conn.close()

    wa_msg = f"مرحباً، أود تفعيل اشتراكي في مادة ({c['title']}) باسم الطالب ({session.get('user_name')}) عبر منصة إتقان، وهذا إشعار التحويل."
    wa_link = f"https://wa.me/{wa_num}?text={wa_msg}"

    bank_cards = []
    for b in banks:
        bank_cards.append(f'''
        <div class="bg-slate-50 border-2 border-slate-200 p-4 rounded-2xl text-xs space-y-2 mb-3">
            <div class="flex justify-between items-center"><span class="text-slate-500 font-bold">البنك / المحفظة:</span><span class="font-black text-slate-900">{b['bank_name']}</span></div>
            <div class="flex justify-between items-center"><span class="text-slate-500 font-bold">المستفيد:</span><span class="font-black text-slate-900">{b['beneficiary']}</span></div>
            <div class="pt-1">
                <span class="text-slate-500 font-bold block mb-0.5">رقم الحساب:</span>
                <div class="bg-white p-2 rounded-xl border border-slate-300 text-center font-mono font-black text-slate-800 select-all tracking-wider">{b['account_num']}</div>
            </div>
            {f"""<div><span class='text-slate-500 font-bold block mb-0.5'>رقم الآيبان (IBAN):</span><div class='bg-white p-2 rounded-xl border border-slate-300 text-center font-mono font-black text-slate-800 select-all tracking-wide text-[11px]'>{b['iban']}</div></div>""" if b['iban'] else ""}
        </div>''')

    banks_html = ''.join(bank_cards) if bank_cards else '<p class="text-xs text-slate-400 text-center py-2">لا توجد حسابات بنكية مضافة حالياً</p>'

    html_page = f'''<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>إتمام الدفع - منصة إتقان</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800;900&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Tajawal', sans-serif; background-color: #F4F6F8; }}
        .bravo-teal-btn {{ background: #4AD7C5; transition: all 0.2s; }}
        .bravo-teal-btn:hover {{ background: #3bc2b1; transform: translateY(-1px); }}
    </style>
</head>
<body class="min-h-screen py-10 px-4">
    <div class="max-w-md mx-auto">
        <div class="text-center mb-6">
            <a href="/" class="inline-block w-14 h-14 bg-white border border-slate-200 rounded-2xl flex items-center justify-center mx-auto mb-3 shadow-sm">
                <span class="text-2xl font-black text-[#0B4B80]">إ</span>
            </a>
            <h1 class="text-xl font-black text-slate-900">التحويل البنكي وتأكيد الاشتراك</h1>
            <p class="text-xs text-slate-500 mt-1">المادة: <b class="text-slate-800">{c['title']}</b> | المبلغ: <b class="text-teal-600 font-black">{c['price']:g} ر.س</b></p>
        </div>

        <div class="bg-white p-6 rounded-[32px] border border-slate-100 shadow-xl">
            <div class="mb-6 space-y-3">
                <h3 class="font-black text-sm text-slate-800 mb-3">اختر طريقة الدفع</h3>
                
                <label id="card-option-box" class="block p-4 border-2 border-teal-500 bg-teal-50/30 rounded-2xl cursor-pointer hover:border-teal-600 transition">
                    <div class="flex items-center gap-3">
                        <input type="radio" id="method-card" name="payment_method" value="card" class="w-4 h-4 text-teal-600" checked>
                        <span class="font-black text-sm text-slate-900">💳 بطاقة مدى / فيزا / ماستر كارد</span>
                    </div>
                    <div id="card-fields" class="mt-3 space-y-2">
                        <input type="text" id="card-num" placeholder="رقم البطاقة (فيزا / ماستر كارد / مدى)" class="w-full p-3 border-2 border-slate-200 rounded-xl text-xs font-mono focus:border-teal-500 outline-none bg-white" maxlength="19">
                        <div class="grid grid-cols-2 gap-2">
                            <input type="text" id="card-exp" placeholder="MM/YY" class="w-full p-3 border-2 border-slate-200 rounded-xl text-xs font-mono focus:border-teal-500 outline-none bg-white" maxlength="5">
                            <input type="text" id="card-cvv" placeholder="CVV" class="w-full p-3 border-2 border-slate-200 rounded-xl text-xs font-mono focus:border-teal-500 outline-none bg-white" maxlength="3">
                        </div>
                        <p id="card-msg" class="text-[11px] text-rose-600 font-bold hidden">يرجى إدخال بيانات البطاقة كاملة لتفعيل الدفع بالبطاقة.</p>
                        <p class="text-[10px] text-slate-400 mt-1">🔒 معلوماتك محمية ومشفرة.</p>
                    </div>
                </label>

                <label id="bank-option-box" class="block p-4 border-2 border-slate-200 rounded-2xl cursor-pointer hover:border-teal-500 transition">
                    <div class="flex items-center gap-3">
                        <input type="radio" id="method-bank" name="payment_method" value="bank" class="w-4 h-4 text-teal-600">
                        <span class="font-black text-sm text-slate-900">🏦 تحويل بنكي / محفظة إلكترونية</span>
                    </div>
                    <div id="bank-fields" class="mt-3 hidden">
                        {banks_html}
                    </div>
                </label>
            </div>

            <div class="space-y-3 pt-4 border-t border-slate-100">
                <a href="{wa_link}" target="_blank" class="w-full flex items-center justify-center gap-2 bg-[#25D366] text-white font-black py-3.5 rounded-xl text-xs border-2 border-slate-900 shadow-[0_4px_0_#0f172a] hover:translate-y-0.5 hover:shadow-[0_2px_0_#0f172a] transition-all">
                    <svg class="w-5 h-5 fill-white" viewBox="0 0 24 24"><path d="M.057 24l1.687-6.163c-1.041-1.804-1.588-3.849-1.587-5.946.003-6.556 5.338-11.891 11.893-11.891 3.181.001 6.167 1.24 8.413 3.488 2.245 2.248 3.481 5.236 3.48 8.414-.003 6.557-5.338 11.892-11.893 11.892-1.99-.001-3.951-.5-5.688-1.448l-6.305 1.654zm6.597-3.807c1.676.995 3.276 1.591 5.392 1.592 5.448 0 9.886-4.434 9.889-9.885.002-5.462-4.415-9.89-9.881-9.892-5.452 0-9.887 4.434-9.889 9.884-.001 2.225.651 3.891 1.746 5.634l-.999 3.648 3.742-.981zm11.387-5.464c-.074-.124-.272-.198-.57-.347-.297-.149-1.758-.868-2.031-.967-.272-.099-.47-.149-.669.149-.198.297-.768.967-.941 1.165-.173.198-.347.223-.644.074-.297-.149-1.255-.462-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.297-.347.446-.521.151-.172.2-.296.3-.495.099-.198.05-.372-.025-.521-.075-.148-.669-1.611-.916-2.206-.242-.579-.487-.501-.669-.51l-.57-.01c-.198 0-.52.074-.792.372s-1.04 1.016-1.04 2.479 1.065 2.876 1.213 3.074c.149.198 2.095 3.2 5.076 4.487.709.306 1.263.489 1.694.626.712.226 1.36.194 1.872.118.571-.085 1.758-.719 2.006-1.413.248-.695.248-1.29.173-1.414z"/></svg>
                    <span>📲 إرسال إشعار التحويل عبر الواتساب</span>
                </a>
                <form id="pay-form" action="/buy/{c['id']}" method="POST">
                    <button type="submit" class="w-full bg-[#0F294A] hover:bg-[#163a66] text-white font-black py-3.5 rounded-xl text-xs shadow-md transition-all">
                        تأكيد التحويل (طلب التفعيل من الإدارة)
                    </button>
                </form>
                <div class="text-center mt-3">
                    <a href="/course/{c['id']}" class="text-[11px] text-slate-400 hover:text-slate-600 font-bold">إلغاء والعودة للمقرر</a>
                </div>
            </div>
        </div>
    </div>

    <script>
        const cardRadio = document.getElementById('method-card');
        const bankRadio = document.getElementById('method-bank');
        const cardFields = document.getElementById('card-fields');
        const bankFields = document.getElementById('bank-fields');
        const cardBox = document.getElementById('card-option-box');
        const bankBox = document.getElementById('bank-option-box');
        const cardNum = document.getElementById('card-num');
        const cardExp = document.getElementById('card-exp');
        const cardCvv = document.getElementById('card-cvv');
        const cardMsg = document.getElementById('card-msg');

        function syncPaymentMethod() {{
            const isCard = cardRadio.checked;
            cardFields.classList.toggle('hidden', !isCard);
            bankFields.classList.toggle('hidden', isCard);
            cardMsg.classList.add('hidden');

            [cardNum, cardExp, cardCvv].forEach(inp => {{
                if (inp) inp.disabled = !isCard;
            }});

            if (isCard) {{
                cardBox.classList.add('border-teal-500', 'bg-teal-50/30');
                cardBox.classList.remove('border-slate-200');
                bankBox.classList.remove('border-teal-500', 'bg-teal-50/30');
                bankBox.classList.add('border-slate-200');
            }} else {{
                bankBox.classList.add('border-teal-500', 'bg-teal-50/30');
                bankBox.classList.remove('border-slate-200');
                cardBox.classList.remove('border-teal-500', 'bg-teal-50/30');
                cardBox.classList.add('border-slate-200');
            }}
        }}

        cardRadio.addEventListener('change', syncPaymentMethod);
        bankRadio.addEventListener('change', syncPaymentMethod);
        syncPaymentMethod();

        cardNum.addEventListener('input', function() {{
            let digits = this.value.replace(/\\D/g, '').slice(0, 16);
            this.value = digits.replace(/(.{{4}})/g, '$1 ').trim();
        }});

        cardExp.addEventListener('input', function() {{
            let digits = this.value.replace(/\\D/g, '').slice(0, 4);
            if (digits.length >= 3) {{
                this.value = digits.slice(0, 2) + '/' + digits.slice(2);
            }} else {{
                this.value = digits;
            }}
        }});

        cardCvv.addEventListener('input', function() {{
            this.value = this.value.replace(/\\D/g, '').slice(0, 3);
        }});

        document.getElementById('pay-form').addEventListener('submit', function(e) {{
            if (cardRadio.checked) {{
                const digitsOnly = cardNum.value.replace(/\\D/g, '');
                const expVal = cardExp.value.trim();
                const cvvVal = cardCvv.value.trim();
                if (digitsOnly.length < 12 || expVal.length < 4 || cvvVal.length < 3) {{
                    e.preventDefault();
                    cardMsg.classList.remove('hidden');
                }}
            }}
        }});
    </script>
</body>
</html>'''

    return html_page


@app.route('/buy/<int:course_id>', methods=['POST'])
def buy(course_id):
    if not session.get('user_id'):
        return redirect(f'/login?next=/checkout/{course_id}')
    conn = get_db()
    conn.execute('''INSERT INTO enrollments (user_id, course_id, status) 
                    VALUES (?, ?, 'pending') 
                    ON CONFLICT(user_id, course_id) DO UPDATE SET status='pending' ''',
                 (session['user_id'], course_id))
    conn.commit()
    conn.close()
    return redirect(f'/course/{course_id}')


@app.route('/login', methods=['GET', 'POST'])
def login():
    next_url = (request.args.get('next') or request.form.get('next') or '').strip()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if name:
            conn = get_db()
            u = conn.execute('SELECT * FROM users WHERE name=?', (name,)).fetchone()
            if not u:
                c = conn.cursor()
                c.execute('INSERT INTO users (name, is_admin) VALUES (?, 0)', (name,))
                conn.commit()
                u_id = c.lastrowid
            else:
                u_id = u['id']
            conn.close()
            session['user_id'] = u_id
            session['user_name'] = name

            if next_url.startswith('/'):
                return redirect(next_url)

            return redirect('/')

    next_hidden = f'<input type="hidden" name="next" value="{next_url}">' if next_url else ''
    login_html = f'''
    <div class="max-w-sm mx-auto px-4 py-16">
        <div class="bg-white p-6 rounded-[32px] border border-slate-100 shadow-xl text-center">
            <div class="w-14 h-14 bg-white border-2 border-slate-100 rounded-2xl flex items-center justify-center mx-auto mb-3 shadow-sm p-1">
                <span class="text-2xl font-black text-[#0B4B80]">إ</span>
            </div>
            <h2 class="text-lg font-black mb-1 text-slate-900">تسجيل الدخول للطلاب</h2>
            <p class="text-xs text-slate-400 mb-6">اكتب اسمك الثلاثي للوصول السريع لحسابك</p>
            <form method="POST" action="/login{f'?next={next_url}' if next_url else ''}" class="space-y-3">
                {next_hidden}
                <input type="text" name="name" placeholder="أدخل اسمك الثلاثي" required class="w-full p-3.5 border-2 border-slate-100 rounded-2xl text-xs font-bold outline-none focus:border-slate-800">
                <button class="bravo-teal-btn w-full font-black py-3 rounded-full text-xs text-slate-900">دخول المنصة</button>
            </form>
        </div>
    </div>
    '''
    return render_template('base.html', content=login_html)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)