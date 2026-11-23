import os
from flask import Flask, send_from_directory
from database import init_db
from admin_panel import register_admin_routes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'admin-panel-secret-2026-ultra-secure'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

init_db()

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# تسجيل لوحة التحكم الشاملة والآمنة على الجذر الرئيسي للسيرفر المستقل (Port 5002)
register_admin_routes(
    app,
    url_prefix='',
    site_url='http://127.0.0.1:5000',
    blueprint_name='admin_standalone_bp',
    upload_folder=UPLOAD_FOLDER
)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5002, debug=False, threaded=True)
