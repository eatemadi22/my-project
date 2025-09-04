from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
import sqlite3
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io, base64, os, json
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# IMPORTANT: change this secret key to a strong random value before deploying
app.secret_key = os.environ.get('SURVEY_SECRET_KEY', 'replace_this_with_a_random_secret_key')

ADMIN_FILE = 'admin.json'
DB_FILE = 'survey.db'

# ---------- admin credential helpers ----------
def ensure_admin_file():
    if not os.path.exists(ADMIN_FILE):
        default = {
            "username": "admin",
            "password_hash": generate_password_hash("12345")
        }
        with open(ADMIN_FILE, 'w', encoding='utf-8') as f:
            json.dump(default, f)
def load_admin():
    with open(ADMIN_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)
def save_admin(username, password_plain):
    data = {
        "username": username,
        "password_hash": generate_password_hash(password_plain)
    }
    with open(ADMIN_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f)

# ---------- database ----------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS responses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  q1 TEXT, q2 TEXT, q3 TEXT, suggestions TEXT)''')
    conn.commit()
    conn.close()

# ---------- simple login_required decorator ----------
def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('admin_logged'):
            return redirect(url_for('admin_login', next=request.path))
        return fn(*args, **kwargs)
    return wrapper

# ---------- survey routes ----------
@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/q1', methods=['GET', 'POST'])
def q1():
    if request.method == 'POST':
        session['q1'] = request.form.get('q1')
        return redirect(url_for('q2'))
    return render_template('question1.html')

@app.route('/q2', methods=['GET', 'POST'])
def q2():
    if request.method == 'POST':
        choices = request.form.getlist('q2')
        # store as pipe-separated string
        session['q2'] = ' | '.join(choices)
        return redirect(url_for('q3'))
    return render_template('question2.html')

@app.route('/q3', methods=['GET', 'POST'])
def q3():
    if request.method == 'POST':
        q3_value = request.form.get('q3')
        if q3_value == "پیشنهاد دیگری دارم":
            other = request.form.get('other_suggestion','').strip()
            if other:
                q3_value = f"{q3_value}: {other}"
        session['q3'] = q3_value
        return redirect(url_for('suggestions'))
    return render_template('question3.html')

@app.route('/suggestions', methods=['GET', 'POST'])
def suggestions():
    if request.method == 'POST':
        suggestions = request.form.get('suggestions','').strip()
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO responses (q1, q2, q3, suggestions) VALUES (?, ?, ?, ?)",
                  (session.get('q1'), session.get('q2'), session.get('q3'), suggestions))
        conn.commit()
        conn.close()
        # clear session answers
        session.pop('q1', None); session.pop('q2', None); session.pop('q3', None)
        return redirect(url_for('thanks'))
    return render_template('suggestions.html')

@app.route('/thanks')
def thanks():
    return render_template('thanks.html')

# ---------- admin (login, logout, change password, dashboard) ----------
@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    ensure_admin_file()
    admin = load_admin()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == admin.get('username') and check_password_hash(admin.get('password_hash'), password):
            session['admin_logged'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('نام کاربری یا رمز عبور اشتباه است', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/change-password', methods=['GET','POST'])
@login_required
def admin_change_password():
    admin = load_admin()
    if request.method == 'POST':
        current = request.form.get('current_password')
        newp = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        if not check_password_hash(admin.get('password_hash'), current):
            flash('رمز فعلی اشتباه است', 'danger')
        elif newp != confirm:
            flash('رمز جدید و تکرار آن یکسان نیستند', 'danger')
        else:
            save_admin(admin.get('username'), newp)
            flash('رمز با موفقیت تغییر کرد', 'success')
            return redirect(url_for('admin_dashboard'))
    return render_template('change_password.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM responses", conn)
    conn.close()
    if df.empty:
        return render_template('admin_empty.html')
    # Prepare display dataframe with Persian headers
    df_display = df.rename(columns={
        'id':'ردیف',
        'q1':'میزان رضایت',
        'q2':'نوع محتوای مورد علاقه',
        'q3':'نظر درباره تغییر نام کانال',
        'suggestions':'پیشنهادات و انتقادات'
    })
    # charts
    charts = {}
    # chart 1: q1 bar
    fig1 = plt.figure(figsize=(6,3.5))
    df['q1'].value_counts().plot(kind='bar')
    plt.title('میزان رضایت (سوال ۱)')
    plt.ylabel('تعداد')
    plt.tight_layout()
    buf1 = io.BytesIO(); plt.savefig(buf1, format='png'); buf1.seek(0)
    charts['q1'] = base64.b64encode(buf1.getvalue()).decode()
    plt.close()

    # chart 2: q2 horizontal bar
    fig2 = plt.figure(figsize=(6,3.5))
    q2_counts = df['q2'].str.split(' \| ').explode().value_counts()
    q2_counts.plot(kind='barh')
    plt.title('علاقه‌مندی‌ها (سوال ۲)')
    plt.xlabel('تعداد')
    plt.tight_layout()
    buf2 = io.BytesIO(); plt.savefig(buf2, format='png'); buf2.seek(0)
    charts['q2'] = base64.b64encode(buf2.getvalue()).decode()
    plt.close()

    # chart 3: q3 pie
    fig3 = plt.figure(figsize=(6,3.5))
    df['q3'].value_counts().plot(kind='pie', autopct='%1.1f%%')
    plt.title('نظر درباره تغییر نام کانال (سوال ۳)')
    plt.ylabel('')
    plt.tight_layout()
    buf3 = io.BytesIO(); plt.savefig(buf3, format='png'); buf3.seek(0)
    charts['q3'] = base64.b64encode(buf3.getvalue()).decode()
    plt.close()

    # convert df_display to html table
    table_html = df_display.to_html(classes='table table-striped table-bordered', index=False, justify='center')
    return render_template('admin.html', table=table_html, charts=charts)

@app.route('/admin/download')
@login_required
def admin_download():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM responses", conn)
    conn.close()
    if df.empty:
        return "No data", 400
    df_export = df.rename(columns={
        'q1':'میزان رضایت',
        'q2':'نوع محتوای مورد علاقه',
        'q3':'نظر درباره تغییر نام کانال',
        'suggestions':'پیشنهادات و انتقادات'
    })
    file_path = 'responses_export.xlsx'
    df_export.to_excel(file_path, index=False)
    return send_file(file_path, as_attachment=True)

# ---------- initialize ----------
if __name__ == '__main__':
    ensure_admin_file()
    init_db()
    app.run(debug=True)