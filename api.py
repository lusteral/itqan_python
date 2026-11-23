import os
import time
import hashlib
import hmac
import json
from flask import Flask, request, jsonify
from database import get_db

app = Flask(__name__)

# مفتاح API السري للتوثيق بين السيرفرين
API_SECRET_KEY = "itqan-secure-api-key-2026-admin-panel-only"
API_KEY = "itqan-api-key-x9k2m4n6p8q0"

def verify_api_key():
    """التحقق من مفتاح API في الطلب"""
    api_key = request.headers.get('X-API-Key')
    if not api_key or api_key != API_KEY:
        return False
    return True

def verify_signature(data, signature):
    """التحقق من توقيع البيانات للتأكد من سلامتها"""
    expected_signature = hmac.new(
        API_SECRET_KEY.encode(),
        json.dumps(data, sort_keys=True).encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_signature, signature)

@app.route('/api/health', methods=['GET'])
def health_check():
    """فحص صحة API"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'status': 'healthy', 'timestamp': time.time()})

@app.route('/api/universities', methods=['GET'])
def get_universities():
    """الحصول على قائمة الجامعات"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    unis = conn.execute('SELECT * FROM universities').fetchall()
    conn.close()
    
    result = [{'id': u['id'], 'name': u['name'], 'logo': u['logo'], 'desc': u['desc']} for u in unis]
    return jsonify(result)

@app.route('/api/universities', methods=['POST'])
def add_university():
    """إضافة جامعة جديدة"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    signature = request.headers.get('X-Signature')
    
    if not verify_signature(data, signature):
        return jsonify({'error': 'Invalid signature'}), 401
    
    conn = get_db()
    conn.execute('INSERT INTO universities (name, logo, desc) VALUES (?, ?, ?)',
                 (data['name'], data.get('logo', '🏛️'), data.get('desc', '')))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/universities/<int:uni_id>', methods=['DELETE'])
def delete_university(uni_id):
    """حذف جامعة"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    conn.execute('DELETE FROM universities WHERE id=?', (uni_id,))
    conn.execute('DELETE FROM courses WHERE uni_id=?', (uni_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/courses', methods=['GET'])
def get_courses():
    """الحصول على قائمة المواد"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    courses = conn.execute('SELECT c.*, u.name as uni_name FROM courses c LEFT JOIN universities u ON c.uni_id=u.id').fetchall()
    conn.close()
    
    result = [{'id': c['id'], 'title': c['title'], 'code': c['code'], 'price': c['price'],
               'uni_id': c['uni_id'], 'uni_name': c['uni_name'], 'faculty': c['faculty']} for c in courses]
    return jsonify(result)

@app.route('/api/courses', methods=['POST'])
def add_course():
    """إضافة مادة جديدة"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    signature = request.headers.get('X-Signature')
    
    if not verify_signature(data, signature):
        return jsonify({'error': 'Invalid signature'}), 401
    
    conn = get_db()
    conn.execute('''INSERT INTO courses (uni_id, title, code, desc, price, faculty) 
                   VALUES (?, ?, ?, ?, ?, ?)''',
                 (data['uni_id'], data['title'], data.get('code', ''), 
                  data.get('desc', ''), data['price'], data.get('faculty', 'كلية الهندسة')))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/courses/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    """حذف مادة"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    conn.execute("DELETE FROM lessons WHERE course_id=?", (course_id,))
    conn.execute("DELETE FROM courses WHERE id=?", (course_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/works', methods=['GET'])
def get_works():
    """الحصول على قائمة الأعمال الفصلية"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    works = conn.execute('SELECT * FROM semester_works ORDER BY id DESC').fetchall()
    conn.close()
    
    result = [{'id': w['id'], 'title': w['title'], 'faculty': w['faculty'], 
               'desc': w['desc'], 'cover_img': w['cover_img']} for w in works]
    return jsonify(result)

@app.route('/api/works', methods=['POST'])
def add_work():
    """إضافة عمل فصلي جديد"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    signature = request.headers.get('X-Signature')
    
    if not verify_signature(data, signature):
        return jsonify({'error': 'Invalid signature'}), 401
    
    conn = get_db()
    conn.execute('''INSERT INTO semester_works (title, faculty, desc, cover_img) 
                   VALUES (?, ?, ?, ?)''',
                 (data['title'], data['faculty'], data['desc'], data.get('cover_img')))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/works/<int:work_id>', methods=['DELETE'])
def delete_work(work_id):
    """حذف عمل فصلي"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    conn.execute('DELETE FROM semester_works WHERE id=?', (work_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/lessons', methods=['GET'])
def get_lessons():
    """الحصول على قائمة الدروس"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    lessons = conn.execute('SELECT l.*, c.title as course_title FROM lessons l LEFT JOIN courses c ON l.course_id=c.id').fetchall()
    conn.close()
    
    result = [{'id': l['id'], 'title': l['title'], 'course_id': l['course_id'], 
               'course_title': l['course_title'], 'video_filename': l['video_filename'], 
               'pdf_filename': l['pdf_filename']} for l in lessons]
    return jsonify(result)

@app.route('/api/lessons', methods=['POST'])
def add_lesson():
    """إضافة درس جديد"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    signature = request.headers.get('X-Signature')
    
    if not verify_signature(data, signature):
        return jsonify({'error': 'Invalid signature'}), 401
    
    conn = get_db()
    conn.execute('''INSERT INTO lessons (course_id, title, video_filename, pdf_filename) 
                   VALUES (?, ?, ?, ?)''',
                 (data['course_id'], data['title'], data.get('video_filename'), data.get('pdf_filename')))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/lessons/<int:lesson_id>', methods=['DELETE'])
def delete_lesson(lesson_id):
    """حذف درس"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    conn.execute('DELETE FROM lessons WHERE id=?', (lesson_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/banks', methods=['GET'])
def get_banks():
    """الحصول على قائمة الحسابات البنكية"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    banks = conn.execute('SELECT * FROM bank_accounts').fetchall()
    conn.close()
    
    result = [{'id': b['id'], 'bank_name': b['bank_name'], 'beneficiary': b['beneficiary'],
               'account_num': b['account_num'], 'iban': b['iban']} for b in banks]
    return jsonify(result)

@app.route('/api/banks', methods=['POST'])
def add_bank():
    """إضافة حساب بنكي جديد"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    signature = request.headers.get('X-Signature')
    
    if not verify_signature(data, signature):
        return jsonify({'error': 'Invalid signature'}), 401
    
    conn = get_db()
    conn.execute('''INSERT INTO bank_accounts (bank_name, beneficiary, account_num, iban) 
                   VALUES (?, ?, ?, ?)''',
                 (data['bank_name'], data['beneficiary'], data['account_num'], data.get('iban', '')))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/banks/<int:bank_id>', methods=['DELETE'])
def delete_bank(bank_id):
    """حذف حساب بنكي"""
    if not verify_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db()
    conn.execute('DELETE FROM bank_accounts WHERE id=?', (bank_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=False)
