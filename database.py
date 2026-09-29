import os 
import sqlite3
import click
from flask import current_app, g


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db
    

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,                      -- NULL for Google-only accounts
    google_id TEXT UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('doctor', 'patient')),
    reset_token TEXT,
    reset_token_expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', '+1 hours'))
);

CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    patient_code TEXT UNIQUE NOT NULL,       -- human-friendly Patient ID e.g. HB-PT-0001
    full_name TEXT NOT NULL,
    date_of_birth TEXT,
    sex TEXT,
    contact_info TEXT,
    address TEXT,
    blood_group TEXT,
    genotype TEXT,
    emergency_contact_name TEXT,
    emergency_contact_phone TEXT,
    medical_history TEXT,
    allergies TEXT,
    chronic_conditions TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', '+1 hours'))
);

CREATE TABLE IF NOT EXISTS doctors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    doctor_code TEXT UNIQUE NOT NULL,        -- e.g. HB-DR-0001
    full_name TEXT NOT NULL,
    specialization TEXT,
    license_number TEXT,
    contact_info TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', '+1 hours'))
);

CREATE TABLE IF NOT EXISTS consultations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    doctor_id INTEGER NOT NULL REFERENCES doctors(id),
    visit_date TEXT NOT NULL,
    reason TEXT,
    diagnosis TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', '+1 hours'))
);

CREATE TABLE IF NOT EXISTS prescriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    doctor_id INTEGER NOT NULL REFERENCES doctors(id),
    consultation_id INTEGER REFERENCES consultations(id),
    medication TEXT NOT NULL,
    dosage TEXT,
    frequency TEXT,
    duration TEXT,
    instructions TEXT,
    date_prescribed TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now', '+1 hours'))
);

CREATE TABLE IF NOT EXISTS lab_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    doctor_id INTEGER NOT NULL REFERENCES doctors(id),
    test_name TEXT NOT NULL,
    result_value TEXT,
    reference_range TEXT,
    lab_notes TEXT,
    test_date TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now', '+1 hours'))
);



CREATE TABLE IF NOT EXISTS access_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doctor_id INTEGER NOT NULL REFERENCES doctors(id) ON DELETE CASCADE,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied','revoked')),
    token TEXT,
    requested_at TEXT NOT NULL DEFAULT (datetime('now', '+1 hours')),
    responded_at TEXT,
    UNIQUE(doctor_id, patient_id)
);


CREATE TABLE IF NOT EXISTS ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    actor_id INTEGER NOT NULL,
    actor_role TEXT NOT NULL,
    action_type TEXT NOT NULL,
    record_type TEXT NOT NULL,     
    record_id INTEGER NOT NULL,
    data_hash TEXT NOT NULL,

"""