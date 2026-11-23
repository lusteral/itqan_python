import os
import sqlite3
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, 'itqan.db')

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def get_site_settings(conn=None):
    close_conn = False
    if conn is None:
        conn = get_db()
        close_conn = True
    try:
        rows = conn.execute('SELECT key, value FROM site_settings').fetchall()
        settings = {r['key']: r['value'] for r in rows}
    except Exception:
        settings = {}
    if close_conn:
        conn.close()
    return settings

def init_db():
    conn = get_db()
    c = conn.cursor()

    # 1. جداول النظام الأساسية
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        is_admin INTEGER DEFAULT 0
    )''')

    # جدول حسابات الأدمن الآمن
    c.execute('''CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT DEFAULT 'مدير النظام',
        role TEXT DEFAULT 'مدير عام',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )''')

    # جدول حماية تسجيل الدخول من الهجمات (Brute-Force Protection)
    c.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
        ip_address TEXT PRIMARY KEY,
        attempts INTEGER DEFAULT 0,
        locked_until REAL DEFAULT 0
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS universities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        logo TEXT,
        desc TEXT,
        logo_img TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS instructors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        bio TEXT,
        avatar_img TEXT,
        banner_img TEXT,
        rating REAL DEFAULT 5.0
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uni_id INTEGER,
        instructor_id INTEGER DEFAULT 1,
        title TEXT,
        code TEXT DEFAULT '',
        desc TEXT, 
        price REAL,
        old_price REAL DEFAULT 0,
        mid_price REAL DEFAULT 0,
        mid_old_price REAL DEFAULT 0,
        final_price REAL DEFAULT 0,
        final_old_price REAL DEFAULT 0,
        cover_img TEXT,
        faculty TEXT DEFAULT 'كلية الهندسة',
        target_audience TEXT DEFAULT 'طلاب وطالبات'
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS lessons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER,
        title TEXT,
        video_filename TEXT,
        pdf_filename TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        course_id INTEGER,
        package_type TEXT DEFAULT 'full',
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, course_id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS bank_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bank_name TEXT,
        beneficiary TEXT,
        account_num TEXT,
        iban TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS semester_works (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        faculty TEXT,
        desc TEXT,
        file_name TEXT,
        cover_img TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # جدول الإعلانات والصور والسلايدر
    c.execute('''CREATE TABLE IF NOT EXISTS ads_banners (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        subtitle TEXT DEFAULT '',
        badge TEXT DEFAULT '',
        badge_color TEXT DEFAULT 'amber',
        image_url TEXT DEFAULT '',
        link_url TEXT DEFAULT '',
        ad_type TEXT DEFAULT 'slider',
        is_active INTEGER DEFAULT 1,
        sort_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # جدول معلومات وإعدادات الموقع العامة
    c.execute('''CREATE TABLE IF NOT EXISTS site_settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')

    # تحديثات الحقول والأعمدة
    alter_columns = [
        'ALTER TABLE universities ADD COLUMN logo_img TEXT',
        'ALTER TABLE courses ADD COLUMN code TEXT DEFAULT ""',
        'ALTER TABLE courses ADD COLUMN instructor_id INTEGER DEFAULT 1',
        'ALTER TABLE courses ADD COLUMN old_price REAL DEFAULT 0',
        'ALTER TABLE courses ADD COLUMN mid_price REAL DEFAULT 0',
        'ALTER TABLE courses ADD COLUMN mid_old_price REAL DEFAULT 0',
        'ALTER TABLE courses ADD COLUMN final_price REAL DEFAULT 0',
        'ALTER TABLE courses ADD COLUMN final_old_price REAL DEFAULT 0',
        'ALTER TABLE courses ADD COLUMN cover_img TEXT',
        'ALTER TABLE courses ADD COLUMN faculty TEXT DEFAULT "كلية الهندسة"',
        'ALTER TABLE courses ADD COLUMN target_audience TEXT DEFAULT "طلاب وطالبات"',
        'ALTER TABLE lessons ADD COLUMN pdf_filename TEXT',
        'ALTER TABLE lessons ADD COLUMN video_filename TEXT',
        'ALTER TABLE enrollments ADD COLUMN status TEXT DEFAULT "approved"',
        'ALTER TABLE semester_works ADD COLUMN cover_img TEXT'
    ]

    for alter_sql in alter_columns:
        try:
            c.execute(alter_sql)
        except Exception:
            pass

    # تهيئة حساب الأدمن الافتراضي (محمي بتشفير PBKDF2-SHA256)
    c.execute('SELECT COUNT(*) FROM admins')
    if c.fetchone()[0] == 0:
        default_hash = generate_password_hash('123', method='pbkdf2:sha256')
        c.execute('''INSERT INTO admins (username, password_hash, full_name, role) 
                     VALUES (?, ?, ?, ?)''', ('admin', default_hash, 'المدير العام', 'مدير عام'))

    # تهيئة الإعدادات والمعلومات الافتراضية للموقع
    default_settings = {
        'site_name': 'إتقان | المنصة التعليمية',
        'academy_name': 'أكاديمية إتقان التعليمية',
        'academy_bio': 'نخبة من الأكاديميين والمحاضرين المتخصصين في تبسيط وشرح المقررات الجامعية وتلخيصها ومتابعة الطلاب لتحقيق الامتياز A+.',
        'whatsapp_number': '966593521664',
        'hero_badge_1': '🏆 المنصة التعليمية الأولى',
        'hero_badge_2': 'أكاديمية إتقان 2026',
        'hero_title': 'شروحات جامعية، أعمال فصلية، ومشاريع احترافية بامتياز A+ 🎯',
        'hero_desc': 'نقدم أفضل الملخصات، الواجبات، الأنشطة والأعمال الفصلية المعتمدة لجميع الجامعات والمقررات باللغتين العربية والإنجليزية.',
        'promo_badge': '🔥 عروض حصريّة',
        'promo_discount': 'خصم 20% لفترة محدودة',
        'slider_title': 'منصة إتقان للأعمال والمشاريع الأكاديمية',
        'slider_badge': 'معرض صور المشاريع 📸',
        'students_count': '+1000',
        'academy_rating': '5.0',
        'legal_warning': 'تحذير قانوني : لا يجوز نشره أو مشاركته',
        'footer_text': 'منصة إتقان الأكاديمية © 2023 - 2026'
    }
    for k, v in default_settings.items():
        c.execute('INSERT OR IGNORE INTO site_settings (key, value) VALUES (?, ?)', (k, v))

    # تهيئة الإعلانات وصور السلايدر الافتراضية
    c.execute('SELECT COUNT(*) FROM ads_banners')
    if c.fetchone()[0] == 0:
        default_ads = [
            ("تصميم وتطوير لوحات التحكم والمواقع المتكاملة", "أنظمة Full-Stack بكود مصدري منظم وتصميم تجاوبي معتمد", "💻 برمجة وتطوير Web Apps", "amber", "https://images.unsplash.com/photo-1551288049-bebda4e38f71?auto=format&fit=crop&w=1200&q=80", "", "slider", 1, 1),
            ("تطوير تطبيقات الجوال واجهات Flutter & React Native", "تطبيقات ذكية، ربط قواعد البيانات، وواجهات UI/UX احترافية", "📱 تطبيقات Android & iOS", "teal", "https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?auto=format&fit=crop&w=1200&q=80", "", "slider", 1, 2),
            ("مشاريع خوارزميات الذكاء الاصطناعي وتحليل البيانات", "نماذج تعلم الآلة، المعالجة البرمجية، وتوثيق الأكواد", "🤖 الذكاء الاصطناعي و Python", "purple", "https://images.unsplash.com/photo-1555066931-4365d14bab8c?auto=format&fit=crop&w=1200&q=80", "", "slider", 1, 3),
            ("تصميم الدوائر الإلكترونية والتحليل الإنشائي والمعملي", "تقارير ودراسات هندسية دقيقة متوافقة مع متطلبات الكليات", "⚙️ المشاريع الهندسيّة والتقنيّة", "sky", "https://images.unsplash.com/photo-1581092160607-ee22621dd758?auto=format&fit=crop&w=1200&q=80", "", "slider", 1, 4),
            ("⚡ تصفح الملازم والأعمال الفصلية والمشاريع الاحترافية المميزة لجميع الكليات!", "", "", "amber", "", "", "ticker", 1, 1),
            ("🎓 تواصل معنا مباشرة عبر الواتساب للحصول على استشارة أو حل واجب خاص 📲", "", "", "amber", "", "", "ticker", 1, 2),
            ("⭐ ضمان جودة الشروحات الأكاديمية أعلى الدرجات A+", "", "", "amber", "", "", "ticker", 1, 3)
        ]
        for title, subtitle, badge, badge_color, image_url, link_url, ad_type, is_active, sort_order in default_ads:
            c.execute('''INSERT INTO ads_banners (title, subtitle, badge, badge_color, image_url, link_url, ad_type, is_active, sort_order)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (title, subtitle, badge, badge_color, image_url, link_url, ad_type, is_active, sort_order))

    # البيانات الابتدائية الافتراضية
    c.execute('SELECT COUNT(*) FROM instructors')
    if c.fetchone()[0] == 0:
        c.execute('''INSERT INTO instructors (name, bio, rating) 
                     VALUES ('أكاديمية إتقان التعليمية', 'نخبة من الأكاديميين والمحاضرين المتخصصين في تبسيط وشرح المقررات الجامعية وتلخيصها ومتابعة الطلاب لتحقيق الامتياز A+.', 5.0)''')

    c.execute('SELECT COUNT(*) FROM bank_accounts')
    if c.fetchone()[0] == 0:
        c.execute('''INSERT INTO bank_accounts (bank_name, beneficiary, account_num, iban) 
                     VALUES ('بنك الجزيرة', 'عدنان محمد سعيد عبدالكريم', '003381468188001', 'SA2160100003381468188001')''')

    c.execute('SELECT COUNT(*) FROM universities')
    if c.fetchone()[0] == 0:
        unis = [
            ("جامعة الملك سعود (KSU)", "👑", "مقررات وشروحات جامعة الملك سعود - الرياض"),
            ("جامعة الملك فهد للبترول والمعادن (KFUPM)", "⚙️", "شروحات ومشاريع جامعة الملك فهد - الظهران"),
            ("جامعة الملك عبدالعزيز (KAU)", "🏢", "مقررات وتكاليف جامعة الملك عبدالعزيز - جدة"),
            ("جامعة الملك خالد (KKU)", "⛰️", "شروحات واختبارات جامعة الملك خالد - أبها"),
            ("جامعة أم القرى (UQU)", "🕋", "شروحات ومقررات جامعة أم القرى - مكة المكرمة"),
            ("جامعة الأميرة نورة (PNU)", "🎓", "مقررات وحاسبات جامعة الأميرة نورة - الرياض"),
            ("جامعة جدة (UJ)", "🏛️", "مقررات وملخصات جامعة جدة"),
            ("جامعة الإمام عبدالرحمن بن فيصل (IAU)", "🌊", "شروحات ومشاريع جامعة الإمام عبدالرحمن - الدمام")
        ]
        for name, logo, desc in unis:
            c.execute('INSERT INTO universities (name, logo, desc) VALUES (?, ?, ?)', (name, logo, desc))

    c.execute('SELECT COUNT(*) FROM semester_works')
    if c.fetchone()[0] == 0:
        sample_works = [
            ("مشروع تطبيق إدارة المهام بلغة React", "كلية علوم الحاسب والمعلومات", "تطبيق متكامل لإدارة المهام اليومية باستخدام React و Redux مع واجهة مستخدم حديثة وتفاعلية", None, "https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&w=800&q=80"),
            ("تقرير دراسة جدوى لمشروع تجارة إلكترونية", "كلية إدارة الأعمال", "دراسة جدوى شاملة لمشروع متجر إلكتروني متخصص في المنتجات التقنية مع تحليل السوق والميزانية", None, "https://images.unsplash.com/photo-1556742049-0cfed4f6a45d?auto=format&fit=crop&w=800&q=80"),
            ("تصميم قاعدة بيانات لنظام إدارة المستشفيات", "كلية هندسة البرمجيات", "تصميم ER-Diagram متكامل لنظام إدارة المستشفيات مع جداول المرضى والأطباء والمواعيد", None, "https://images.unsplash.com/photo-1576091160399-112ba8d25d1d?auto=format&fit=crop&w=800&q=80"),
            ("مشروع تحليل البيانات باستخدام Python", "كلية علوم البيانات", "تحليل مجموعة بيانات العملاء باستخدام Pandas و Matplotlib مع تقارير تفاعلية", None, "https://images.unsplash.com/photo-1551288049-bebda4e38f71?auto=format&fit=crop&w=800&q=80"),
            ("تصميم واجهة مستخدم لتطبيق توصيل طلبات", "كلية التصميم الجرافيكي", "تصميم UI/UX احترافي لتطبيق توصيل طلبات باستخدام Figma مع موديلات تفاعلية", None, "https://images.unsplash.com/photo-1586717791821-3f44a5638d48?auto=format&fit=crop&w=800&q=80"),
            ("تقرير هندسي لمبنى سكني متعدد الطوابق", "كلية الهندسة المدنية", "تقرير هندسي شامل يتضمن المخططات الإنشائية والتحليل الإحصائي للمواد", None, "https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?auto=format&fit=crop&w=800&q=80")
        ]
        for title, faculty, desc, file_name, cover_img in sample_works:
            c.execute('INSERT INTO semester_works (title, faculty, desc, file_name, cover_img) VALUES (?, ?, ?, ?, ?)',
                     (title, faculty, desc, file_name, cover_img))

    c.execute('SELECT COUNT(*) FROM courses')
    if c.fetchone()[0] == 0:
        sample_courses = [
            (1, "الذكاء الاصطناعي وتعلم الآلة (AI 401)", "CSC401", "شرح متكامل لمبادئ الذكاء الاصطناعي وخوارزميات تعلم الآلة والشبكات العصبية مع تطبيق عملي بلغة Python.", 220.0, 280.0, 110.0, 140.0, 140.0, 180.0, "", "كلية علوم الحاسب والمعلومات"),
            (2, "الأمن السيبراني وتشفير البيانات (SEC 311)", "COE311", "شرح مبادئ التشفير، أمن الشبكات، بروتوكولات الحماية، والتحليل الجنائي الرقمي مع حل التجميعات النهائية.", 200.0, 250.0, 100.0, 130.0, 130.0, 160.0, "", "كلية هندسة الحاسب"),
            (3, "تطوير تطبيقات الويب والهواتف الذكية (WEB 210)", "CPIT210", "دورة مكثفة لشرح HTML5, CSS3, JavaScript, React وتكامل البرمجة مع قواعد البيانات والـ API.", 180.0, 230.0, 90.0, 120.0, 120.0, 150.0, "", "كلية الحاسبات وتقنية المعلومات"),
            (4, "حساب التكالمين والتفاضل (Math 101)", "MATH101", "شرح شامل ومبسط لمقرر التفاضل والتكامل مع حل أسئلة الاختيارات والتجميعات السابقة والامتحانات النهائية.", 150.0, 200.0, 80.0, 100.0, 100.0, 120.0, "", "كلية الهندسة والعلوم")
        ]
        for uni_id, title, code, desc, price, old_price, mid_p, mid_old, fin_p, fin_old, cover_img, faculty in sample_courses:
            c.execute('''INSERT INTO courses (uni_id, title, code, desc, price, old_price, mid_price, mid_old_price, final_price, final_old_price, cover_img, faculty) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                      (uni_id, title, code, desc, price, old_price, mid_p, mid_old, fin_p, fin_old, cover_img, faculty))

    conn.commit()
    conn.close()
