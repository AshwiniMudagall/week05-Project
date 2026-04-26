"""
app.py - FieldOps Manager
Week 5 Features:
  - Role-Based Access (admin vs electrician)
  - Advanced Dashboard with chart data
  - API Optimization (clean JSON endpoints)
  - Security Improvements (werkzeug hashing, input validation)
  - File Upload Feature (job images + reports)
  - Code Cleanup with comments and error messages
"""

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import init_db, get_db
from functools import wraps
from datetime import date
import os

# ─── APP CONFIG ───────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'fieldops_secret_week5_secure'

# File upload configuration
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max file size

# Create uploads folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize the database on startup
init_db()


# ─── HELPER FUNCTIONS ─────────────────────────────────────────────────────────

def allowed_file(filename):
    """Return True if file extension is in the allowed list."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_notifications():
    """
    Fetch system notifications for the sidebar badge and notifications page.
    Returns a list of dicts with 'type' and 'msg' keys.
    """
    db = get_db()
    notes = []

    pending_tasks = db.execute("SELECT COUNT(*) FROM tasks WHERE status='Pending'").fetchone()[0]
    if pending_tasks > 0:
        notes.append({'type': 'info', 'msg': f'{pending_tasks} task(s) are Pending'})

    done = db.execute("SELECT COUNT(*) FROM tasks WHERE status='Completed'").fetchone()[0]
    if done > 0:
        notes.append({'type': 'success', 'msg': f'{done} task(s) completed'})

    today = date.today().isoformat()
    overdue = db.execute(
        "SELECT COUNT(*) FROM jobs WHERE deadline <= ? AND status != 'Completed'", (today,)
    ).fetchone()[0]
    if overdue > 0:
        notes.append({'type': 'danger', 'msg': f'{overdue} job(s) have passed or reached deadline!'})

    db.close()
    return notes


# ─── ACCESS CONTROL DECORATORS ────────────────────────────────────────────────

def login_required(f):
    """Redirect to login page if the user is not in session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Allow only users with role='admin'. Redirect electricians to their task view."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        if session.get('user_role') != 'admin':
            flash('Access denied. This page is for admins only.', 'danger')
            return redirect(url_for('electrician_tasks'))
        return f(*args, **kwargs)
    return decorated


# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        # Input validation
        if not email or not password:
            flash('Both email and password are required.', 'danger')
            return render_template('login.html')

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        db.close()

        # Verify password using werkzeug (supports both old sha256 and new hashed)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_role'] = user['role']

            # Role-based redirect after login
            if user['role'] == 'admin':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('electrician_tasks'))

        flash('Invalid email or password. Please try again.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip().lower()
        role = request.form.get('role', 'electrician')
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        # Input validation
        if not name or not email or not password:
            flash('Name, email, and password are required.', 'danger')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('register.html')

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        # Securely hash the password before storing
        hashed = generate_password_hash(password)

        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (name, phone, email, role, password) VALUES (?,?,?,?,?)',
                (name, phone, email, role, hashed)
            )
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception:
            flash('Email already exists. Please use a different email.', 'danger')
        finally:
            db.close()

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))


# ─── ELECTRICIAN VIEW (Role-Based) ────────────────────────────────────────────

@app.route('/my-tasks')
@login_required
def electrician_tasks():
    """
    Electrician-only view. Shows only the tasks assigned to the logged-in electrician.
    Linked by matching email in users table with electricians table.
    """
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()

    # Match electrician profile to user account via email
    electrician = db.execute(
        'SELECT * FROM electricians WHERE email=?', (user['email'],)
    ).fetchone()

    tasks = []
    if electrician:
        tasks = db.execute('''
            SELECT tasks.*, jobs.title AS job_title
            FROM tasks
            LEFT JOIN jobs ON tasks.job_id = jobs.id
            WHERE tasks.electrician_id = ?
            ORDER BY tasks.id DESC
        ''', (electrician['id'],)).fetchall()

    db.close()
    return render_template('electrician_tasks.html', tasks=tasks, electrician=electrician)


@app.route('/my-tasks/update/<int:tid>', methods=['POST'])
@login_required
def electrician_update_task(tid):
    """Allow electricians to update the status of their own tasks."""
    status = request.form.get('status', '')

    if status not in ['Pending', 'In Progress', 'Completed']:
        flash('Invalid status value selected.', 'danger')
        return redirect(url_for('electrician_tasks'))

    db = get_db()
    db.execute('UPDATE tasks SET status=? WHERE id=?', (status, tid))
    db.execute(
        "INSERT INTO activity (message) VALUES (?)",
        (f"Task #{tid} updated to '{status}' by {session.get('user_name', 'electrician')}",)
    )
    db.commit()
    db.close()
    flash(f"Task status updated to '{status}'.", 'success')
    return redirect(url_for('electrician_tasks'))


# ─── ADMIN DASHBOARD ──────────────────────────────────────────────────────────

@app.route('/dashboard')
@admin_required
def dashboard():
    """Admin dashboard: stats cards + chart data for Chart.js."""
    db = get_db()

    # Summary counts for stat cards
    elec = db.execute('SELECT COUNT(*) FROM electricians').fetchone()[0]
    jobs = db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]
    tasks = db.execute('SELECT COUNT(*) FROM tasks').fetchone()[0]
    done = db.execute("SELECT COUNT(*) FROM tasks WHERE status='Completed'").fetchone()[0]
    mats = db.execute('SELECT COUNT(*) FROM materials').fetchone()[0]
    recent = db.execute('SELECT * FROM activity ORDER BY id DESC LIMIT 5').fetchall()

    # Task statistics for doughnut chart
    pending_tasks = db.execute("SELECT COUNT(*) FROM tasks WHERE status='Pending'").fetchone()[0]
    inprog_tasks = db.execute("SELECT COUNT(*) FROM tasks WHERE status='In Progress'").fetchone()[0]

    # Job statistics for bar chart
    jobs_pending = db.execute("SELECT COUNT(*) FROM jobs WHERE status='Pending'").fetchone()[0]
    jobs_inprog = db.execute("SELECT COUNT(*) FROM jobs WHERE status='In Progress'").fetchone()[0]
    jobs_done = db.execute("SELECT COUNT(*) FROM jobs WHERE status='Completed'").fetchone()[0]

    db.close()
    notifications = get_notifications()

    return render_template('dashboard.html',
        electricians=elec, jobs=jobs, tasks=tasks,
        completed=done, materials=mats, recent=recent,
        notifications=notifications,
        pending_tasks=pending_tasks, inprog_tasks=inprog_tasks,
        jobs_pending=jobs_pending, jobs_inprog=jobs_inprog, jobs_done=jobs_done
    )


# ─── ELECTRICIANS (Admin Only) ────────────────────────────────────────────────

@app.route('/electricians')
@admin_required
def electricians():
    db = get_db()
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', 'All')

    query = 'SELECT * FROM electricians WHERE 1=1'
    params = []

    if search:
        query += ' AND (name LIKE ? OR phone LIKE ? OR specialization LIKE ?)'
        params += [f'%{search}%', f'%{search}%', f'%{search}%']

    if status_filter != 'All':
        query += ' AND status=?'
        params.append(status_filter)

    data = db.execute(query, params).fetchall()
    db.close()
    return render_template('electricians.html', electricians=data,
                           search=search, status_filter=status_filter)


@app.route('/electricians/add', methods=['POST'])
@admin_required
def add_electrician():
    name = request.form.get('name', '').strip()
    phone = request.form.get('phone', '').strip()
    email = request.form.get('email', '').strip()
    specialization = request.form.get('specialization', '').strip()

    if not name:
        flash('Electrician name is required.', 'danger')
        return redirect(url_for('electricians'))

    db = get_db()
    db.execute(
        'INSERT INTO electricians (name, phone, email, specialization) VALUES (?,?,?,?)',
        (name, phone, email, specialization)
    )
    db.execute("INSERT INTO activity (message) VALUES (?)", (f"Electrician '{name}' added",))
    db.commit()
    db.close()
    flash(f"Electrician '{name}' added successfully.", 'success')
    return redirect(url_for('electricians'))


@app.route('/electricians/edit/<int:eid>', methods=['GET', 'POST'])
@admin_required
def edit_electrician(eid):
    db = get_db()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        specialization = request.form.get('specialization', '').strip()
        status = request.form.get('status', 'Active')

        if not name:
            flash('Electrician name is required.', 'danger')
            db.close()
            return redirect(url_for('edit_electrician', eid=eid))

        db.execute('''UPDATE electricians SET name=?, phone=?, email=?, specialization=?, status=?
                      WHERE id=?''', (name, phone, email, specialization, status, eid))
        db.execute("INSERT INTO activity (message) VALUES (?)", (f"Electrician '{name}' updated",))
        db.commit()
        db.close()
        flash(f"Electrician '{name}' updated successfully.", 'success')
        return redirect(url_for('electricians'))

    electrician = db.execute('SELECT * FROM electricians WHERE id=?', (eid,)).fetchone()
    db.close()
    if not electrician:
        flash('Electrician not found.', 'danger')
        return redirect(url_for('electricians'))
    return render_template('edit_electrician.html', electrician=electrician)


@app.route('/electricians/delete/<int:eid>')
@admin_required
def delete_electrician(eid):
    db = get_db()
    row = db.execute('SELECT name FROM electricians WHERE id=?', (eid,)).fetchone()
    if row:
        db.execute('DELETE FROM electricians WHERE id=?', (eid,))
        db.execute("INSERT INTO activity (message) VALUES (?)", (f"Electrician '{row['name']}' deleted",))
        db.commit()
        flash(f"Electrician '{row['name']}' deleted.", 'success')
    else:
        flash('Electrician not found.', 'danger')
    db.close()
    return redirect(url_for('electricians'))


# ─── JOBS (Admin Only) ────────────────────────────────────────────────────────

@app.route('/jobs')
@admin_required
def jobs():
    db = get_db()
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', 'All')

    query = '''SELECT jobs.*, electricians.name AS electrician_name
               FROM jobs LEFT JOIN electricians ON jobs.electrician_id = electricians.id
               WHERE 1=1'''
    params = []

    if search:
        query += ' AND (jobs.title LIKE ? OR jobs.location LIKE ?)'
        params += [f'%{search}%', f'%{search}%']

    if status_filter != 'All':
        query += ' AND jobs.status=?'
        params.append(status_filter)

    data = db.execute(query, params).fetchall()
    electricians_list = db.execute('SELECT * FROM electricians').fetchall()
    db.close()
    return render_template('jobs.html', jobs=data, electricians=electricians_list,
                           search=search, status_filter=status_filter)


@app.route('/jobs/add', methods=['POST'])
@admin_required
def add_job():
    title = request.form.get('title', '').strip()
    location = request.form.get('location', '').strip()
    deadline = request.form.get('deadline', '')
    electrician_id = request.form.get('electrician_id') or None

    if not title:
        flash('Job title is required.', 'danger')
        return redirect(url_for('jobs'))

    # Optional job image upload
    image_filename = None
    if 'job_image' in request.files:
        file = request.files['job_image']
        if file and file.filename and allowed_file(file.filename):
            image_filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

    db = get_db()
    db.execute(
        'INSERT INTO jobs (title, location, deadline, electrician_id, image_filename) VALUES (?,?,?,?,?)',
        (title, location, deadline, electrician_id, image_filename)
    )
    db.execute("INSERT INTO activity (message) VALUES (?)", (f"Job '{title}' created",))
    db.commit()
    db.close()
    flash(f"Job '{title}' created successfully.", 'success')
    return redirect(url_for('jobs'))


@app.route('/jobs/edit/<int:jid>', methods=['GET', 'POST'])
@admin_required
def edit_job(jid):
    db = get_db()
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        location = request.form.get('location', '').strip()
        deadline = request.form.get('deadline', '')
        electrician_id = request.form.get('electrician_id') or None
        status = request.form.get('status', 'Pending')

        if not title:
            flash('Job title is required.', 'danger')
            db.close()
            return redirect(url_for('edit_job', jid=jid))

        db.execute('''UPDATE jobs SET title=?, location=?, deadline=?,
                      electrician_id=?, status=? WHERE id=?''',
                   (title, location, deadline, electrician_id, status, jid))
        db.execute("INSERT INTO activity (message) VALUES (?)", (f"Job '{title}' updated",))
        db.commit()
        db.close()
        flash(f"Job '{title}' updated.", 'success')
        return redirect(url_for('jobs'))

    job = db.execute('SELECT * FROM jobs WHERE id=?', (jid,)).fetchone()
    electricians_list = db.execute('SELECT * FROM electricians').fetchall()
    db.close()
    if not job:
        flash('Job not found.', 'danger')
        return redirect(url_for('jobs'))
    return render_template('edit_job.html', job=job, electricians=electricians_list)


@app.route('/jobs/delete/<int:jid>')
@admin_required
def delete_job(jid):
    db = get_db()
    row = db.execute('SELECT title FROM jobs WHERE id=?', (jid,)).fetchone()
    if row:
        db.execute('DELETE FROM jobs WHERE id=?', (jid,))
        db.execute("INSERT INTO activity (message) VALUES (?)", (f"Job '{row['title']}' deleted",))
        db.commit()
        flash(f"Job '{row['title']}' deleted.", 'success')
    else:
        flash('Job not found.', 'danger')
    db.close()
    return redirect(url_for('jobs'))



@app.route('/jobs/status/<int:jid>', methods=['POST'])
@admin_required
def update_job_status(jid):
    status = request.form.get('status', '')

    if status not in ['Pending', 'In Progress', 'Completed']:
        flash('Invalid status selected.', 'danger')
        return redirect(url_for('jobs'))

    db = get_db()
    row = db.execute('SELECT title FROM jobs WHERE id=?', (jid,)).fetchone()
    if row:
        db.execute('UPDATE jobs SET status=? WHERE id=?', (status, jid))
        db.execute("INSERT INTO activity (message) VALUES (?)",
                   (f"Job '{row['title']}' status changed to '{status}'",))
        db.commit()
        flash(f"Job status updated to '{status}'.", 'success')
    else:
        flash('Job not found.', 'danger')
    db.close()
    return redirect(url_for('jobs'))

# ─── TASKS (Admin Only) ───────────────────────────────────────────────────────

@app.route('/tasks')
@admin_required
def tasks():
    db = get_db()
    status_filter = request.args.get('status', 'All')
    search = request.args.get('search', '').strip()

    query = '''SELECT tasks.*, jobs.title AS job_title, electricians.name AS electrician_name
               FROM tasks
               LEFT JOIN jobs ON tasks.job_id = jobs.id
               LEFT JOIN electricians ON tasks.electrician_id = electricians.id
               WHERE 1=1'''
    params = []

    if status_filter != 'All':
        query += ' AND tasks.status=?'
        params.append(status_filter)

    if search:
        query += ' AND tasks.task LIKE ?'
        params.append(f'%{search}%')

    data = db.execute(query, params).fetchall()
    jobs_list = db.execute('SELECT * FROM jobs').fetchall()
    electricians_list = db.execute('SELECT * FROM electricians').fetchall()
    db.close()
    return render_template('tasks.html', tasks=data,
                           jobs=jobs_list, electricians=electricians_list,
                           status_filter=status_filter, search=search)


@app.route('/tasks/add', methods=['POST'])
@admin_required
def add_task():
    task = request.form.get('task', '').strip()
    job_id = request.form.get('job_id') or None
    electrician_id = request.form.get('electrician_id') or None
    status = request.form.get('status', 'Pending')

    if not task:
        flash('Task description is required.', 'danger')
        return redirect(url_for('tasks'))

    db = get_db()
    db.execute('INSERT INTO tasks (task, job_id, electrician_id, status) VALUES (?,?,?,?)',
               (task, job_id, electrician_id, status))
    db.execute("INSERT INTO activity (message) VALUES (?)", (f"Task '{task[:30]}' assigned",))
    db.commit()
    db.close()
    flash('Task assigned successfully.', 'success')
    return redirect(url_for('tasks'))


@app.route('/tasks/update_status/<int:tid>', methods=['POST'])
@admin_required
def update_task_status(tid):
    status = request.form.get('status', '')

    if status not in ['Pending', 'In Progress', 'Completed']:
        flash('Invalid status selected.', 'danger')
        return redirect(url_for('tasks'))

    db = get_db()
    db.execute('UPDATE tasks SET status=? WHERE id=?', (status, tid))
    db.execute("INSERT INTO activity (message) VALUES (?)", (f"Task #{tid} updated to '{status}'",))
    db.commit()
    db.close()
    flash(f'Task #{tid} updated to {status}.', 'success')
    return redirect(url_for('tasks'))


@app.route('/tasks/delete/<int:tid>')
@admin_required
def delete_task(tid):
    db = get_db()
    db.execute('DELETE FROM tasks WHERE id=?', (tid,))
    db.commit()
    db.close()
    flash(f'Task #{tid} deleted.', 'success')
    return redirect(url_for('tasks'))


# ─── MATERIALS (Admin Only) ───────────────────────────────────────────────────

@app.route('/materials')
@admin_required
def materials():
    db = get_db()
    data = db.execute('SELECT * FROM materials').fetchall()
    db.close()
    return render_template('materials.html', materials=data)


@app.route('/materials/add', methods=['POST'])
@admin_required
def add_material():
    name = request.form.get('name', '').strip()
    unit = request.form.get('unit', 'pcs')

    if not name:
        flash('Material name is required.', 'danger')
        return redirect(url_for('materials'))

    try:
        quantity = int(request.form.get('quantity', 0))
    except ValueError:
        flash('Quantity must be a valid number.', 'danger')
        return redirect(url_for('materials'))

    db = get_db()
    db.execute('INSERT INTO materials (name, quantity, unit) VALUES (?,?,?)', (name, quantity, unit))
    db.execute("INSERT INTO activity (message) VALUES (?)", (f"Material '{name}' added",))
    db.commit()
    db.close()
    flash(f"Material '{name}' added.", 'success')
    return redirect(url_for('materials'))


@app.route('/materials/use/<int:mid>', methods=['POST'])
@admin_required
def use_material(mid):
    try:
        amount = int(request.form.get('amount', 0))
    except ValueError:
        flash('Amount must be a valid number.', 'danger')
        return redirect(url_for('materials'))

    if amount <= 0:
        flash('Amount must be greater than zero.', 'danger')
        return redirect(url_for('materials'))

    db = get_db()
    mat = db.execute('SELECT * FROM materials WHERE id=?', (mid,)).fetchone()

    if not mat:
        flash('Material not found.', 'danger')
        db.close()
        return redirect(url_for('materials'))

    if mat['quantity'] < amount:
        flash(f"Not enough stock for '{mat['name']}'. Available: {mat['quantity']} {mat['unit']}.", 'danger')
        db.close()
        return redirect(url_for('materials'))

    db.execute('UPDATE materials SET used=?, quantity=? WHERE id=?',
               (mat['used'] + amount, mat['quantity'] - amount, mid))
    db.execute("INSERT INTO activity (message) VALUES (?)",
               (f"Used {amount} {mat['unit']} of '{mat['name']}'",))
    db.commit()
    db.close()
    flash(f"Used {amount} {mat['unit']} of '{mat['name']}'.", 'success')
    return redirect(url_for('materials'))


@app.route('/materials/delete/<int:mid>')
@admin_required
def delete_material(mid):
    db = get_db()
    row = db.execute('SELECT name FROM materials WHERE id=?', (mid,)).fetchone()
    if row:
        db.execute('DELETE FROM materials WHERE id=?', (mid,))
        db.execute("INSERT INTO activity (message) VALUES (?)", (f"Material '{row['name']}' deleted",))
        db.commit()
        flash(f"Material '{row['name']}' deleted.", 'success')
    db.close()
    return redirect(url_for('materials'))


# ─── FILE UPLOAD ──────────────────────────────────────────────────────────────

@app.route('/upload', methods=['GET', 'POST'])
@admin_required
def upload_file():
    """Upload job images or report files. Files saved to static/uploads/."""
    db = get_db()

    if request.method == 'POST':
        job_id = request.form.get('job_id') or None
        file_type = request.form.get('file_type', 'image')

        if 'file' not in request.files:
            flash('No file part found. Please select a file.', 'danger')
            return redirect(url_for('upload_file'))

        file = request.files['file']

        if not file or not file.filename:
            flash('No file selected.', 'danger')
            return redirect(url_for('upload_file'))

        if not allowed_file(file.filename):
            flash('File type not allowed. Please upload PNG, JPG, GIF, or PDF only.', 'danger')
            return redirect(url_for('upload_file'))

        # Save the file securely
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        # Record in uploads table
        db.execute(
            'INSERT INTO uploads (filename, original_name, file_type, job_id, uploaded_by) VALUES (?,?,?,?,?)',
            (filename, file.filename, file_type, job_id, session['user_id'])
        )
        db.execute("INSERT INTO activity (message) VALUES (?)", (f"File '{filename}' uploaded",))
        db.commit()
        flash(f"File '{file.filename}' uploaded successfully.", 'success')

    # Fetch all uploads with job title
    uploads = db.execute('''
        SELECT uploads.*, jobs.title AS job_title
        FROM uploads
        LEFT JOIN jobs ON uploads.job_id = jobs.id
        ORDER BY uploads.id DESC
    ''').fetchall()
    jobs_list = db.execute('SELECT * FROM jobs').fetchall()
    db.close()
    return render_template('upload.html', uploads=uploads, jobs=jobs_list)


# ─── REPORTS (Admin Only) ─────────────────────────────────────────────────────

@app.route('/reports')
@admin_required
def reports():
    db = get_db()

    # Task completion counts
    pending = db.execute("SELECT COUNT(*) FROM tasks WHERE status='Pending'").fetchone()[0]
    in_prog = db.execute("SELECT COUNT(*) FROM tasks WHERE status='In Progress'").fetchone()[0]
    completed = db.execute("SELECT COUNT(*) FROM tasks WHERE status='Completed'").fetchone()[0]

    # Per-electrician activity with progress
    elec_activity = db.execute('''
        SELECT electricians.name,
               COUNT(tasks.id) AS total_tasks,
               SUM(CASE WHEN tasks.status='Completed' THEN 1 ELSE 0 END) AS done
        FROM electricians
        LEFT JOIN tasks ON tasks.electrician_id = electricians.id
        GROUP BY electricians.id
    ''').fetchall()

    # Recent activity log
    activity = db.execute('SELECT * FROM activity ORDER BY id DESC LIMIT 10').fetchall()

    # Job status breakdown
    jobs_pending = db.execute("SELECT COUNT(*) FROM jobs WHERE status='Pending'").fetchone()[0]
    jobs_inprog = db.execute("SELECT COUNT(*) FROM jobs WHERE status='In Progress'").fetchone()[0]
    jobs_completed = db.execute("SELECT COUNT(*) FROM jobs WHERE status='Completed'").fetchone()[0]

    db.close()
    return render_template('reports.html',
        pending=pending, in_prog=in_prog, completed=completed,
        elec_activity=elec_activity, activity=activity,
        jobs_pending=jobs_pending, jobs_inprog=jobs_inprog,
        jobs_completed=jobs_completed
    )


# ─── NOTIFICATIONS ────────────────────────────────────────────────────────────

@app.route('/notifications')
@login_required
def notifications():
    notes = get_notifications()
    return render_template('notifications.html', notifications=notes)


# ─── PROFILE ──────────────────────────────────────────────────────────────────

@app.route('/profile')
@login_required
def profile():
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    db.close()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('logout'))
    return render_template('profile.html', user=user)


# ─── JSON API ENDPOINTS ───────────────────────────────────────────────────────

@app.route('/api/stats')
@admin_required
def api_stats():
    """
    GET /api/stats
    Returns dashboard statistics in JSON format.
    """
    db = get_db()
    data = {
        'electricians': db.execute('SELECT COUNT(*) FROM electricians').fetchone()[0],
        'jobs': {
            'total':       db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],
            'pending':     db.execute("SELECT COUNT(*) FROM jobs WHERE status='Pending'").fetchone()[0],
            'in_progress': db.execute("SELECT COUNT(*) FROM jobs WHERE status='In Progress'").fetchone()[0],
            'completed':   db.execute("SELECT COUNT(*) FROM jobs WHERE status='Completed'").fetchone()[0],
        },
        'tasks': {
            'total':       db.execute('SELECT COUNT(*) FROM tasks').fetchone()[0],
            'pending':     db.execute("SELECT COUNT(*) FROM tasks WHERE status='Pending'").fetchone()[0],
            'in_progress': db.execute("SELECT COUNT(*) FROM tasks WHERE status='In Progress'").fetchone()[0],
            'completed':   db.execute("SELECT COUNT(*) FROM tasks WHERE status='Completed'").fetchone()[0],
        },
        'materials': db.execute('SELECT COUNT(*) FROM materials').fetchone()[0],
    }
    db.close()
    return jsonify({'success': True, 'data': data})


@app.route('/api/tasks')
@admin_required
def api_tasks():
    """
    GET /api/tasks
    Returns all tasks as JSON.
    """
    db = get_db()
    rows = db.execute('''
        SELECT tasks.id, tasks.task, tasks.status,
               jobs.title AS job, electricians.name AS electrician
        FROM tasks
        LEFT JOIN jobs ON tasks.job_id = jobs.id
        LEFT JOIN electricians ON tasks.electrician_id = electricians.id
    ''').fetchall()
    db.close()
    return jsonify({'success': True, 'data': [dict(r) for r in rows]})


@app.route('/api/jobs')
@admin_required
def api_jobs():
    """
    GET /api/jobs
    Returns all jobs as JSON.
    """
    db = get_db()
    rows = db.execute('''
        SELECT jobs.id, jobs.title, jobs.location, jobs.deadline,
               jobs.status, electricians.name AS electrician
        FROM jobs
        LEFT JOIN electricians ON jobs.electrician_id = electricians.id
    ''').fetchall()
    db.close()
    return jsonify({'success': True, 'data': [dict(r) for r in rows]})


# ─── ERROR HANDLERS ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def page_not_found(e):
    """Show custom 404 page for missing routes."""
    return render_template('404.html'), 404


@app.errorhandler(413)
def file_too_large(e):
    """Handle file uploads that exceed the 5MB limit."""
    flash('File is too large. Maximum allowed size is 5MB.', 'danger')
    return redirect(url_for('upload_file'))


# ─── RUN ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(debug=True)