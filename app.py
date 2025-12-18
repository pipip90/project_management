from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import sqlite3
import hashlib
from datetime import date
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DATABASE = 'project.db'

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'docx'}  # теперь разрешены только docx
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            group_name TEXT
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            description TEXT,
            student_id INTEGER,
            deadline DATE,
            file_path TEXT,
            FOREIGN KEY(student_id) REFERENCES users(id)
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            teacher_id INTEGER,
            submission_date DATE,
            grade INTEGER,
            status TEXT,
            comment TEXT,
            FOREIGN KEY(project_id) REFERENCES projects(id),
            FOREIGN KEY(teacher_id) REFERENCES users(id)
        )
    ''')
    admin = db.execute('SELECT * FROM users WHERE username=?', ('admin',)).fetchone()
    if not admin:
        db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                   ('admin', hashlib.sha256('admin'.encode()).hexdigest(), 'admin'))
    db.commit()

# ---------------- Регистрация ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role')
        group_name = request.form.get('group_name') if role=='student' else None
        hashed = hashlib.sha256(password.encode()).hexdigest()
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password, role, group_name) VALUES (?, ?, ?, ?)',
                       (username, hashed, role, group_name))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return 'Пользователь с таким именем уже существует'
    return render_template('register.html')

# ---------------- Вход ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        hashed = hashlib.sha256(password.encode()).hexdigest()
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username=? AND password=?',
                          (username, hashed)).fetchone()
        if user:
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['group_name'] = user['group_name']
            return redirect(url_for('index'))
        else:
            return 'Неверный логин или пароль'
    return render_template('login.html')

# ---------------- Выход ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------------- Главная ----------------
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session['role'] == 'student':
        return redirect(url_for('student_projects'))
    elif session['role'] == 'teacher':
        return redirect(url_for('teacher_projects'))
    elif session['role'] == 'admin':
        return redirect(url_for('admin'))
    return 'Неизвестная роль'

# ---------------- Студент ----------------
@app.route('/student')
def student_projects():
    if 'user_id' not in session or session['role'] != 'student':
        return 'Доступ запрещён'
    db = get_db()
    projects = db.execute('SELECT * FROM projects WHERE student_id=?', (session['user_id'],)).fetchall()
    project_info = []
    for p in projects:
        submission = db.execute('SELECT * FROM submissions WHERE project_id=? ORDER BY submission_date DESC LIMIT 1', (p['id'],)).fetchone()
        project_info.append((p, submission))
    return render_template('student_projects.html', project_info=project_info)

@app.route('/add_project', methods=['GET', 'POST'])
def add_project():
    if 'user_id' not in session or session['role'] != 'student':
        return 'Доступ запрещён'
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        deadline = request.form.get('deadline', '').strip()
        file = request.files.get('file')

        if not title or not description or not deadline:
            return 'Все поля обязательны!'

        file_filename = None
        if file and file.filename:
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                if not filename.lower().endswith('.docx'):
                    filename += '.docx'
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                file_filename = filename
            else:
                return 'Можно загружать только .docx файлы'

        db = get_db()
        db.execute('''
            INSERT INTO projects (title, description, student_id, deadline, file_path)
            VALUES (?, ?, ?, ?, ?)
        ''', (title, description, session['user_id'], deadline, file_filename))
        db.commit()
        return redirect(url_for('student_projects'))
    return render_template('add_project.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# ---------------- Преподаватель ----------------
@app.route('/teacher')
def teacher_projects():
    if 'user_id' not in session or session['role'] != 'teacher':
        return 'Доступ запрещён'
    db = get_db()
    projects = db.execute('''
        SELECT p.id, p.title, p.description, p.deadline, p.file_path,
               u.username AS student_name, u.group_name
        FROM projects p
        JOIN users u ON p.student_id = u.id
    ''').fetchall()
    return render_template('teacher_projects.html', projects=projects)

@app.route('/view_project/<int:project_id>', methods=['GET', 'POST'])
def view_project(project_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        return 'Доступ запрещён'
    db = get_db()
    project = db.execute('''
        SELECT p.id, p.title, p.description, p.deadline, p.file_path,
               u.username AS student_name, u.group_name
        FROM projects p
        JOIN users u ON p.student_id = u.id
        WHERE p.id=?
    ''', (project_id,)).fetchone()
    if not project:
        return 'Проект не найден'
    if request.method == 'POST':
        grade = request.form.get('grade')
        status = request.form.get('status')
        comment = request.form.get('comment', '').strip()
        if not grade or not status:
            return 'Заполните все поля'
        try:
            grade = int(grade)
        except ValueError:
            return 'Оценка должна быть числом'
        if status not in ['pending', 'approved', 'rejected']:
            return 'Неверный статус'
        db.execute('''
            INSERT INTO submissions (project_id, teacher_id, submission_date, grade, status, comment)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (project['id'], session['user_id'], date.today(), grade, status, comment))
        db.commit()
        return redirect(url_for('teacher_projects'))
    return render_template('view_project.html', project=project)

# ---------------- Админ ----------------
@app.route('/admin')
def admin():
    if 'user_id' not in session or session['role'] != 'admin':
        return 'Доступ запрещён'
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    projects = db.execute('''
        SELECT p.*, u.username AS student_name, u.group_name
        FROM projects p
        JOIN users u ON p.student_id = u.id
    ''').fetchall()
    submissions = db.execute('SELECT * FROM submissions').fetchall()
    return render_template('admin.html', users=users, projects=projects, submissions=submissions)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
