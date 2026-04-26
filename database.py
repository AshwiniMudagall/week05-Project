"""
database.py - FieldOps Manager
Handles DB initialization and connection.
Week 5: Added uploads table, image_filename in jobs, timestamps in activity.
"""

import sqlite3

DATABASE = 'fieldops.db'


def get_db():
    """Return a new database connection with row factory enabled."""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    """Create all tables if they don't already exist."""
    db = get_db()

    # Users: stores admin and electrician login accounts
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        name     TEXT NOT NULL,
        phone    TEXT,
        email    TEXT UNIQUE NOT NULL,
        role     TEXT NOT NULL DEFAULT 'electrician',
        password TEXT NOT NULL
    )''')

    # Electricians: worker profiles managed by admin
    db.execute('''CREATE TABLE IF NOT EXISTS electricians (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        name           TEXT NOT NULL,
        phone          TEXT,
        email          TEXT,
        specialization TEXT,
        status         TEXT DEFAULT 'Active',
        rating         REAL DEFAULT 0.0
    )''')

    # Jobs: work orders that can be assigned to electricians
    db.execute('''CREATE TABLE IF NOT EXISTS jobs (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        title           TEXT NOT NULL,
        location        TEXT,
        deadline        TEXT,
        electrician_id  INTEGER,
        status          TEXT DEFAULT 'Pending',
        image_filename  TEXT,
        FOREIGN KEY (electrician_id) REFERENCES electricians(id)
    )''')

    # Tasks: individual tasks under jobs
    db.execute('''CREATE TABLE IF NOT EXISTS tasks (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        task           TEXT NOT NULL,
        job_id         INTEGER,
        electrician_id INTEGER,
        status         TEXT DEFAULT 'Pending',
        FOREIGN KEY (job_id) REFERENCES jobs(id),
        FOREIGN KEY (electrician_id) REFERENCES electricians(id)
    )''')

    # Materials: inventory tracking
    db.execute('''CREATE TABLE IF NOT EXISTS materials (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        name     TEXT NOT NULL,
        quantity INTEGER DEFAULT 0,
        used     INTEGER DEFAULT 0,
        unit     TEXT DEFAULT 'pcs'
    )''')

    # Activity log: audit trail of all actions
    db.execute('''CREATE TABLE IF NOT EXISTS activity (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        message    TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')

    # Uploads: stores uploaded job images and report files
    db.execute('''CREATE TABLE IF NOT EXISTS uploads (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        filename      TEXT NOT NULL,
        original_name TEXT,
        file_type     TEXT,
        job_id        INTEGER,
        uploaded_by   INTEGER,
        uploaded_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (job_id) REFERENCES jobs(id),
        FOREIGN KEY (uploaded_by) REFERENCES users(id)
    )''')

    db.commit()
    db.close()