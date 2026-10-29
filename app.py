import os
import resend
import threading
import time
import uuid
import json
from datetime import datetime, date, timedelta
from functools import wraps
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify, abort, send_file
)
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from dotenv import load_dotenv

from extensions import db
from models import User, Rule, Audit, Alert, MailLog, NCR, FiveSAudit
from sqlalchemy import case


load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))

# Ensure the directory holding the SQLite file exists so the database can
# be created on first deploy (gunicorn/WSGI imports the app, it does not
# run `python app.py`).
db_path = os.path.join(basedir, 'instance', 'database.db')
os.makedirs(os.path.dirname(db_path), exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True}
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=12)

IDLE_TIMEOUT_SECONDS = 30 * 60

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_RULE_EXTENSIONS = {'csv', 'json', 'txt'}
ALLOWED_ATTACHMENT_EXTENSIONS = {'pdf', 'docx', 'doc', 'txt', 'csv', 'json', 'png', 'jpg', 'jpeg', 'gif', 'webp'}

PLANTS = ['Plant 1', 'Plant 2', 'Plant 3']

# Zone names can be replaced here once the final list is confirmed.
ZONES = [f'Zone {i}' for i in range(1, 21)]

# Zonal leader names can be replaced here once the final list is confirmed.
ZONAL_LEADERS = [
    'Mr. Jigar Paramar',
    'Mr. Srikanth S',
    'mr vishwanth shetty',
    'mr. jinesh R',
    'Mr. vijay murthy',
    'Mr. pavankumar',
    'Mr.Avinash p',
    'Mr.Ajay&Mr.Reguram',
    'Mr. Vijay Moorthy',
    'Mr.shethuraman',
    'mr.surendra',
    'Mr.Rajendra',
]

STATUS_OPTIONS = ['open', 'closed']

AUDIT_TYPES = ['5S Audit', 'HOD Audit']


# 5S audit check sheet - identical format for every zone/section.
FIVE_S_CHECKLIST = [
    (
        '1. Sort (Seiri) - Remove Unnecessary Items',
        [
            ('1-1-1', 'Red Tagging/Scrap tag', 'No unnecessary items are left or stored in the workplace.'),
            ('1-1-2', 'Workstation Clearance', 'Are only the tools/materials necessary for the current job present at the machine?'),
            ('1-1-3', 'Floor Clutter', 'Are the areas around machines free from unnecessary items, old machinery parts, toolings or excess raw material?'),
            ('1-1-4', 'Document Control', 'Are old, revised, or non-essential production drawings, inspection reports, work instructions, checklists removed?'),
        ],
    ),
    (
        '2. Set in Order (Seiton) - Organize and Arrange',
        [
            ('2-1-1', 'Tool Organization', 'Are required toolings, instruments, wheels or wheel packs stored in labeled containers/racks or shadow boards at the point of use?'),
            ('2-1-2', 'Workstation Layout', 'Are tools arranged in order of use to minimize operator motion?'),
            ('2-1-3', 'Material Flow', 'Are raw materials, work-in-progress (WIP), and finished tools clearly segregated and labelled to avoid mixing?'),
            ('2-1-4', 'Safety Accessibility', 'Are fire extinguishers, first-aid kits, and electrical panels easily accessible and not blocked by tooling or materials?'),
            ('2-1-5', 'Floor Markings', 'Are aisles, walkways, and hazard zones clearly marked and respected?'),
        ],
    ),
    (
        '3. Shine (Seiso) - Clean and Inspect',
        [
            ('3-1-1', 'Machine & racks Cleanliness', 'Are all machines free of excess oil, swarf (metal shavings), and coolant buildup? Are racks, cabinets and shelves kept clean. Stored items, materials & products are kept clean'),
            ('3-1-2', 'Cleaning Responsibilities', 'Is it clear who is responsible for cleaning each machine, workstation, and shared area?'),
            ('3-1-3', 'Hazardous Materials', 'Are coolants, oils, and solvents stored properly and free from leaks?'),
            ('3-1-4', 'Lighting and Visibility', 'Are light fixtures clean and working, ensuring adequate light for inspection?'),
            ('3-1-5', 'Inspection Routine', 'Are daily cleaning routines combined with maintenance inspections to identify leaks, wear, or damaged parts?'),
        ],
    ),
    (
        '4. Standardize (Seiketsu) - Create Standards',
        [
            ('4-1-1', 'SOP Visibility', 'Are standard operating procedures, including cleaning schedules, posted at workstations?'),
            ('4-1-2', 'Visual Controls', 'Are color-coding systems for tools or materials consistently applied?'),
            ('4-1-3', 'Audit Frequency', 'Are regular 5S audits (Daily/weekly/monthly) scheduled and performed?'),
            ('4-1-4', 'Measurement Tools', 'Are precision instruments (calipers, micrometers) stored according to a defined, protected standard?'),
        ],
    ),
    (
        '5. Sustain (Shitsuke) - Maintain and Improve',
        [
            ('5-1-1', 'Training', 'Are all employees trained on 5S procedures and understand their responsibilities?'),
            ('5-1-2', 'Follow-up on Audits', 'Are the actions identified in the previous audit completed?'),
            ('5-1-3', 'Employee Participation', 'Do employees participate in improvement ideas for their own workstations?'),
            ('5-1-4', 'Culture', 'Is 5S treated as a daily habit rather than just an audit activity?'),
        ],
    ),
    (
        '6. Safety (6th S) - Often Integrated',
        [
            ('6-1-1', 'PPE Compliance', 'Are operators wearing proper PPE (safety glasses, hearing protection, gloves, mask) when handling tools and coolant?'),
            ('6-1-2', 'Machine Guards', 'Are all guards and safety devices on grinding/cutting machines in place and functional?'),
            ('6-1-3', 'Chemical Safety', 'Are MSDS (Material Safety Data Sheets) readily available for cutting oils and chemicals?'),
        ],
    ),
]

SCORING_SYSTEM = [
    ('5', 'Excellent', 'Fully compliant, standard achieved.'),
    ('4', 'Good', 'Minor issues present.'),
    ('3', 'Average', 'Significant inconsistencies.'),
    ('2', 'Poor', 'Major gaps, non-compliant.'),
    ('1', 'Very Poor', 'No adherence.'),
]


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def allowed_rule_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_RULE_EXTENSIONS


def save_upload(file_storage):
    if not file_storage or file_storage.filename == '':
        return None
    if not allowed_file(file_storage.filename):
        return None
    ext = file_storage.filename.rsplit('.', 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{ext}"
    file_storage.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return filename


def save_rule_upload(file_storage):
    if not file_storage or file_storage.filename == '':
        return None
    if not allowed_rule_file(file_storage.filename):
        return None
    ext = file_storage.filename.rsplit('.', 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{ext}"
    file_storage.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return filename


def allowed_attachment_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_ATTACHMENT_EXTENSIONS


def save_attachment(file_storage):
    if not file_storage or file_storage.filename == '':
        return None
    if not allowed_attachment_file(file_storage.filename):
        return None
    ext = file_storage.filename.rsplit('.', 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{ext}"
    file_storage.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return filename


def parse_date(value):
    if not value:
        return None
    for fmt in ('%d-%m-%Y', '%Y-%m-%d'):
        try:
            return datetime.strptime(value, fmt).date()
        except (ValueError, TypeError):
            continue
    return None


db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.after_request
def set_security_headers(response):
    if response.headers.get('Content-Type', '').startswith('text/html'):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response


def send_email(to_email, subject, body_text, body_html=None):
    resend_api_key = os.getenv('RESEND_API_KEY', '').strip()
    from_email = os.getenv('RESEND_FROM_EMAIL', 'onboarding@resend.dev').strip()

    log_entry = MailLog(
        recipient=to_email,
        subject=subject,
        body=body_text,
        status='failed',
        error=None,
    )

    if not resend_api_key:
        error_msg = 'RESEND_API_KEY not configured in .env'
        log_entry.error = error_msg
        db.session.add(log_entry)
        db.session.commit()
        print(f"[EMAIL LOGGED] To: {to_email} | Subject: {subject}")
        print(f"  Body: {body_text}")
        return False, error_msg

    try:
        import resend
        resend.api_key = resend_api_key
        params = {
            "from": from_email,
            "to": [to_email],
            "subject": subject,
            "text": body_text,
        }
        if body_html:
            params["html"] = body_html
        resend.Emails.send(params)
        log_entry.status = 'sent'
        db.session.add(log_entry)
        db.session.commit()
        print(f"[EMAIL SENT] To: {to_email} | Subject: {subject}")
        return True, None
    except Exception as e:
        error_msg = str(e)
        log_entry.error = error_msg
        db.session.add(log_entry)
        db.session.commit()
        print(f"[EMAIL FAILED] {error_msg}")
        return False, error_msg


REMINDER_DAYS = int(os.getenv('ALERT_REMINDER_DAYS', '6'))
REMINDER_CHECK_INTERVAL = int(os.getenv('ALERT_REMINDER_INTERVAL_SECONDS', '300'))
_scheduler_started = False


def send_due_alert_reminders():
    """Send one reminder email for each alert that is still open (not
    acknowledged) and was created at least ALERT_REMINDER_DAYS ago.
    Each alert is reminded only once, stamped via reminder_sent_at, and
    only the responsible_email on record receives it."""
    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(days=REMINDER_DAYS)
        due = (Alert.query
               .filter(Alert.acknowledged.is_(False),
                       Alert.reminder_sent_at.is_(None),
                       Alert.created_at <= cutoff)
               .all())
        for alert in due:
            audit = db.session.get(Audit, alert.audit_id)
            if not audit:
                alert.reminder_sent_at = datetime.utcnow()
                db.session.commit()
                continue
            subject = f"[Reminder] Overdue: {alert.subject}"
            created_str = alert.created_at.strftime('%Y-%m-%d %H:%M:%S')
            body_text = (
                f"REMINDER: This alert is still OPEN and overdue "
                f"(opened {REMINDER_DAYS} day(s) ago).\n\n"
                f"Subject: {alert.subject}\n"
                f"Responsible HOD: {audit.responsible_hod}\n"
                f"Responsible Email: {alert.responsible_email}\n"
                f"Created: {created_str}\n"
                f"Audit Status: {audit.status}\n\n"
                f"Details:\n{alert.message}\n\n"
                "Please take immediate action and acknowledge this alert once resolved."
            )
            body_html = (
                f"<h3>REMINDER: {alert.subject}</h3>"
                f"<p>This alert is still <strong>OPEN</strong> and overdue "
                f"(opened {REMINDER_DAYS} day(s) ago).</p>"
                f"<p><strong>Responsible HOD:</strong> {audit.responsible_hod}<br>"
                f"<strong>Email:</strong> {alert.responsible_email}<br>"
                f"<strong>Created:</strong> {created_str}<br>"
                f"<strong>Audit Status:</strong> {audit.status}</p>"
                f"<p>{alert.message.replace(chr(10), '<br>')}</p>"
                f"<p>Please take immediate action and acknowledge this alert once resolved.</p>"
            )
            sent, error_msg = send_email(alert.responsible_email, subject, body_text, body_html)
            if sent:
                alert.reminder_sent_at = datetime.utcnow()
                db.session.commit()
            status = 'sent' if sent else f'failed: {error_msg}'
            print(f"[REMINDER] alert#{alert.id} -> {alert.responsible_email} ({status})")


def _reminder_loop():
    while True:
        try:
            send_due_alert_reminders()
        except Exception as e:
            print(f"[REMINDER] check failed: {e}")
        time.sleep(REMINDER_CHECK_INTERVAL)


def _start_alert_reminder_scheduler():
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True
    threading.Thread(target=_reminder_loop, daemon=True).start()


def normalize_choice(value, options):
    import re

    value = (value or '').strip()
    if value in options:
        return value
    match = re.fullmatch(r'([A-Za-z ]*?)(\d+)', value)
    if match:
        candidate = f"{match.group(1).strip()} {int(match.group(2))}"
        if candidate in options:
            return candidate
    return value


def run_migrations():
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)
    if 'audit' not in inspector.get_table_names():
        return

    columns = {c['name'] for c in inspector.get_columns('audit')}
    if 'zone' not in columns:
        with db.engine.begin() as conn:
            conn.execute(text("ALTER TABLE audit ADD COLUMN zone VARCHAR(100) DEFAULT ''"))
        print('[OK] Migration: added audit.zone column')

    legacy_zone_columns = [f'zone{i}' for i in range(1, 21) if f'zone{i}' in columns]
    if legacy_zone_columns:
        coalesce_expr = "COALESCE(" + ", ".join("NULLIF(%s, '')" % c for c in legacy_zone_columns) + ")"
        with db.engine.begin() as conn:
            conn.execute(text(
                f"UPDATE audit SET zone = {coalesce_expr} "
                f"WHERE COALESCE(NULLIF(zone, ''), '') = ''"
            ))
        print(f"[OK] Migration: backfilled audit.zone from {legacy_zone_columns}")

    with db.session.begin():
        for audit in Audit.query.all():
            zone = normalize_choice(audit.zone, ZONES)
            if zone != audit.zone and zone in ZONES:
                audit.zone = zone
            plant = normalize_choice(audit.plant, PLANTS)
            if plant != audit.plant and plant in PLANTS:
                audit.plant = plant
            leader = normalize_choice(audit.zonal_leader, ZONAL_LEADERS)
            if leader != audit.zonal_leader and leader in ZONAL_LEADERS:
                audit.zonal_leader = leader

    if 'alert' in inspector.get_table_names():
        alert_cols = {c['name'] for c in inspector.get_columns('alert')}
        if 'reminder_sent_at' not in alert_cols:
            with db.engine.begin() as conn:
                conn.execute(text("ALTER TABLE alert ADD COLUMN reminder_sent_at DATETIME"))
            print('[OK] Migration: added alert.reminder_sent_at column')

    if 'rule' in inspector.get_table_names():
        rule_cols = {c['name'] for c in inspector.get_columns('rule')}
        if 'file_attachment' not in rule_cols:
            with db.engine.begin() as conn:
                conn.execute(text("ALTER TABLE rule ADD COLUMN file_attachment VARCHAR(200)"))
            print('[OK] Migration: added rule.file_attachment column')

    # Ensure the ygct_plant* columns exist (added in a later schema version).
    if 'audit' in inspector.get_table_names():
        audit_cols = {c['name'] for c in inspector.get_columns('audit')}
        for plant_col in ('ygct_plant1', 'ygct_plant2', 'ygct_plant3'):
            if plant_col not in audit_cols:
                with db.engine.begin() as conn:
                    conn.execute(text(
                        f"ALTER TABLE audit ADD COLUMN {plant_col} VARCHAR(100) DEFAULT ''"
                    ))
                print(f'[OK] Migration: added audit.{plant_col} column')

    # Ensure the audit_type column exists (HOD Audit / 5S Audit sub-types).
    if 'audit' in inspector.get_table_names():
        audit_cols = {c['name'] for c in inspector.get_columns('audit')}
        if 'audit_type' not in audit_cols:
            with db.engine.begin() as conn:
                conn.execute(text("ALTER TABLE audit ADD COLUMN audit_type VARCHAR(20) DEFAULT '5S Audit'"))
            print('[OK] Migration: added audit.audit_type column')

    # Ensure the 5S audit check sheet table has the columns used by FiveSAudit.
    if 'five_s_audit' in inspector.get_table_names():
        five_s_cols = {c['name'] for c in inspector.get_columns('five_s_audit')}
        with db.engine.begin() as conn:
            if 'responses' not in five_s_cols:
                conn.execute(text("ALTER TABLE five_s_audit ADD COLUMN responses TEXT DEFAULT '{}'"))
                print('[OK] Migration: added five_s_audit.responses column')
            if 'percentage' not in five_s_cols:
                conn.execute(text("ALTER TABLE five_s_audit ADD COLUMN percentage FLOAT DEFAULT 0"))
                print('[OK] Migration: added five_s_audit.percentage column')


def get_status_counts(audit_type=None):
    query = Audit.query
    if audit_type:
        query = query.filter(Audit.audit_type == audit_type)
    total = query.count()
    open_count = query.filter_by(status='open').count()
    closed_count = query.filter_by(status='closed').count()
    return {
        'total': total,
        'open': open_count,
        'closed': closed_count,
    }


def get_alert_counts(audit_type=None):
    """Pending alert counts for the dashboard.

    `open`     -> alerts still pending (not acknowledged)
    `overdue`  -> pending alerts older than ALERT_REMINDER_DAYS (i.e. due a reminder)
    `acknowledged` -> resolved alerts
    """
    cutoff = datetime.utcnow() - timedelta(days=REMINDER_DAYS)
    base = Alert.query
    if audit_type:
        base = base.join(Audit, Alert.audit_id == Audit.id).filter(
            Audit.audit_type == audit_type
        )
    open_count = base.filter(Alert.acknowledged.is_(False)).count()
    overdue_count = base.filter(
        Alert.acknowledged.is_(False),
        Alert.created_at <= cutoff,
    ).count()
    acknowledged_count = base.filter(Alert.acknowledged.is_(True)).count()
    return {
        'open': open_count,
        'overdue': overdue_count,
        'acknowledged': acknowledged_count,
    }


@app.before_request
def enforce_idle_timeout():
    if not current_user.is_authenticated:
        return None
    if request.endpoint in ('static', 'login'):
        return None
    now = time.time()
    last_seen = session.get('last_seen')
    if last_seen is not None and now - last_seen > IDLE_TIMEOUT_SECONDS:
        logout_user()
        session.clear()
        flash('Your session expired due to inactivity. Please sign in again.', 'warning')
        return redirect(url_for('login'))
    session['last_seen'] = now
    return None


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('hod_audit'))

    if request.method == 'POST':
        user_id = request.form.get('id', '').strip()
        password = request.form.get('password', '')

        if not user_id or not password:
            flash('Please enter both ID and password.', 'error')
            return render_template('login.html')

        user = User.query.filter_by(username=user_id).first()
        if not user or not user.check_password(password):
            flash('Invalid ID or password.', 'error')
            return render_template('login.html')

        if not user.is_active:
            flash('Your account has been deactivated. Contact an administrator.', 'error')
            return render_template('login.html')

        login_user(user, remember=request.form.get('remember') == 'on')
        session['last_login'] = datetime.utcnow().isoformat()
        session['last_seen'] = time.time()
        flash('Login successful!', 'success')

        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('hod_audit'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/')
@login_required
def dashboard():
    """The dashboard page was retired - / now forwards to the HOD Audit overview."""
    return redirect(url_for('hod_audit'))


@app.route('/hod-audit')
@login_required
def hod_audit():
    """HOD Audit view - shows the same overview the dashboard shows."""
    audits = Audit.query.order_by(Audit.created_at.desc()).limit(10).all()
    alerts = Alert.query.order_by(Alert.sent_at.desc()).limit(10).all()
    counts = get_status_counts(audit_type='HOD Audit')

    return render_template(
        'hod_audit.html',
        audits=audits,
        alerts=alerts,
        counts=counts,
        alert_counts=get_alert_counts(audit_type='HOD Audit'),
        audit_types=AUDIT_TYPES,
        current_audit_type='HOD Audit',
        now=datetime.utcnow()
    )


@app.route('/hod-audit-summary')
@app.route('/hod-audit/check-sheet')
@app.route('/hod-audit-summary/')
@login_required
def hod_audit_summary():
    """HOD Audit Summary - shows the full audit record table for HOD audits."""
    hod_query = request.args.get('hod', '').strip()
    query = Audit.query.filter(Audit.audit_type == 'HOD Audit').order_by(Audit.created_at.desc())
    if hod_query:
        query = query.filter(Audit.responsible_hod.ilike(f'%{hod_query}%'))
    all_audits = query.all()
    return render_template(
        'hod_audit_summary.html',
        audits=all_audits,
        plants=PLANTS,
        zones=ZONES,
        zonal_leaders=ZONAL_LEADERS,
        audit_types=AUDIT_TYPES,
        hod_query=hod_query,
    )


@app.route('/5s-audit')
@login_required
def five_s_audit():
    audits = []
    alerts = Alert.query.order_by(Alert.sent_at.desc()).limit(10).all()
    counts = get_status_counts(audit_type='5S Audit')
    zone_query = request.args.get('zone', '').strip()

    return render_template(
        'five_s_audit.html',
        audits=audits,
        alerts=alerts,
        counts=counts,
        alert_counts=get_alert_counts(audit_type='5S Audit'),
        audit_types=AUDIT_TYPES,
        current_audit_type='5S Audit',
        zones=ZONES,
        zone_query=zone_query,
        now=datetime.utcnow()
    )


@app.route('/5s-audit-check-sheet/<int:record_id>')
@login_required
def five_s_check_sheet_detail(record_id):
    record = db.session.get(FiveSAudit, record_id)
    if not record:
        flash('5S audit record not found.', 'error')
        return redirect(url_for('five_s_audit_summary'))
    responses = json.loads(record.responses or '{}')
    checklist = FIVE_S_CHECKLIST
    scoring = SCORING_SYSTEM
    return render_template(
        'five_s_check_sheet_detail.html',
        record=record,
        responses=responses,
        checklist=checklist,
        scoring=scoring,
    )


@app.route('/5s-audit-summary')
@login_required
def five_s_audit_summary():
    """5S Audit Summary - lists saved 5S audit check sheets."""
    hod_query = request.args.get('hod', '').strip()
    zone_query = request.args.get('zone', '').strip()
    query = FiveSAudit.query.order_by(FiveSAudit.created_at.desc())
    if zone_query:
        query = query.filter(FiveSAudit.zone == zone_query)
    all_audits = query.all()
    return render_template(
        'five_s_audit_summary.html',
        audits=all_audits,
        zones=ZONES,
        hod_query=hod_query,
        zone_query=zone_query,
    )


@app.route('/5s-audit-check-sheet')
@login_required
def five_s_check_sheet():
    """5S Audit Check Sheet form - identical format for every zone."""
    return render_template(
        'five_s_check_sheet.html',
        zones=ZONES,
        checklist=FIVE_S_CHECKLIST,
        scoring=SCORING_SYSTEM,
        now=datetime.utcnow(),
    )



@app.route('/5s-audit-check-sheet/save', methods=['POST'])
@login_required
def save_five_s_check_sheet():
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    try:
        # Read form fields
        audit_date = parse_date(request.form.get('audit_date', ''))
        auditor = request.form.get('auditor', '').strip()
        plant = request.form.get('plant', '').strip()
        zone = request.form.get('zone', '').strip()
        auditee = request.form.get('auditee', '').strip()

        # Validate required fields
        errors = []

        if not audit_date:
            errors.append('Date is required.')

        if not auditor:
            errors.append('Auditor is required.')

        if zone not in ZONES:
            errors.append('Please select a valid Zone/Section.')

        if not auditee:
            errors.append('Auditee is required.')

        if errors:
            if is_ajax:
                return jsonify({
                    'ok': False,
                    'message': 'Please correct the following errors.',
                    'errors': errors
                }), 400

            for error in errors:
                flash(error, 'error')

            return redirect(url_for('five_s_check_sheet'))

        # Collect checklist responses and calculate score
        responses = {}
        total_score = 0
        max_score = 0

        for section_name, items in FIVE_S_CHECKLIST:
            for item_id, item_name, question in items:
                score_raw = request.form.get(
                    f'score_{item_id}', ''
                ).strip()

                score = int(score_raw) if score_raw.isdigit() else 0

                # Keep the score within the expected 0–5 range
                if score < 0 or score > 5:
                    errors.append(
                        f'Invalid score for checklist item: {item_name}'
                    )
                    continue

                remarks = request.form.get(
                    f'remark_{item_id}', ''
                ).strip()

                responses[item_id] = {
                    'score': score,
                    'remarks': remarks
                }

                total_score += score
                max_score += 5

        if errors:
            if is_ajax:
                return jsonify({
                    'ok': False,
                    'message': 'Please correct the invalid checklist scores.',
                    'errors': errors
                }), 400

            for error in errors:
                flash(error, 'error')

            return redirect(url_for('five_s_check_sheet'))

        # Calculate percentage
        percentage = (
            round((total_score / max_score) * 100, 1)
            if max_score else 0.0
        )

        # Create database record
        record = FiveSAudit(
            audit_date=audit_date,
            plant=plant,
            auditor=auditor,
            zone=zone,
            status='open',
            scores='',
            remarks='',
            auditee=auditee,
            responses=json.dumps(responses),
            total_score=float(total_score),
            max_score=float(max_score),
            percentage=percentage,
        )

        db.session.add(record)

        # Commit must succeed before returning a success response
        db.session.commit()

        message = '5S audit check sheet saved successfully!'

        if is_ajax:
            return jsonify({
                'ok': True,
                'message': message,
                'id': record.id
            }), 200

        flash(message, 'success')
        return redirect(url_for('five_s_audit_summary'))

    except Exception:
        # Undo any incomplete database transaction
        db.session.rollback()

        if is_ajax:
            return jsonify({
                'ok': False,
                'message': (
                    'Unable to save the 5S audit. '
                    'Please try again.'
                )
            }), 500

        flash(
            'Unable to save the 5S audit. Please try again.',
            'error'
        )
        return redirect(url_for('five_s_check_sheet'))


@app.route('/process-audit')
@login_required
def process_audit():
    """Process Audit view - content will be added later."""
    return render_template('process_audit.html', now=datetime.utcnow())


@app.route('/product-audit')
@login_required
def product_audit():
    """Product Audit view - content will be added later."""
    return render_template('product_audit.html', now=datetime.utcnow())


@app.route('/gemba')
@login_required
def gemba():
    """Gemba view - content will be added later."""
    return render_template('gemba.html', now=datetime.utcnow())


@app.route('/ncr')
@login_required
def ncr():
    """NCR view - shows the inline-editable Non-Conformance Report table."""
    document_no_query = request.args.get('document_no', '').strip()
    query = NCR.query.order_by(NCR.created_at.desc())
    if document_no_query:
        query = query.filter(NCR.document_no.ilike(f'%{document_no_query}%'))
    ncrs = query.all()
    return render_template(
        'ncr.html',
        ncrs=ncrs,
        document_no_query=document_no_query,
        now=datetime.utcnow(),
    )


@app.route('/ncr/save', methods=['POST'])
@login_required
def save_ncr():
    ncr_id = request.form.get('ncr_id', type=int)
    ncr = db.session.get(NCR, ncr_id) if ncr_id else None
    if ncr_id and not ncr:
        flash('NCR record not found.', 'error')
        return redirect(url_for('ncr'))

    document_no = request.form.get('document_no', '').strip()
    date_of_creation = parse_date(request.form.get('date_of_creation', ''))
    product = request.form.get('product', '').strip()
    tool_type = request.form.get('tool_type', '').strip()
    issued_by = request.form.get('issued_by', '').strip()
    issued_dept = request.form.get('issued_dept', '').strip()
    wo_no = request.form.get('wo_no', '').strip()
    edp_no = request.form.get('edp_no', '').strip()
    date_of_submission = parse_date(request.form.get('date_of_submission', ''))
    as_on_date_days = request.form.get('as_on_date_days', '').strip()
    four_m = request.form.get('four_m', '').strip()
    type_of_defect = request.form.get('type_of_defect', '').strip()
    defect_reason = request.form.get('defect_reason', '').strip()
    wo_quantity = request.form.get('wo_quantity', '').strip()
    problem_quantity = request.form.get('problem_quantity', '').strip()
    problem_rate = request.form.get('problem_rate', '').strip()
    process_generated = request.form.get('process_generated', '').strip()
    operator = request.form.get('operator', '').strip()
    processing_result = request.form.get('processing_result', '').strip()
    final_result = request.form.get('final_result', '').strip()
    status = request.form.get('status', 'open')
    reminder_1 = request.form.get('reminder_1', '').strip()
    completed_date = parse_date(request.form.get('completed_date', ''))

    errors = []
    if not document_no:
        errors.append('Document No is required.')
    if not date_of_creation:
        errors.append('Date of Creation is required.')
    if not product:
        errors.append('Product is required.')
    if not tool_type:
        errors.append('Tool Type is required.')
    if not issued_by:
        errors.append('Issued By is required.')
    if not issued_dept:
        errors.append('Issued Dept is required.')
    if not wo_no:
        errors.append('WO No is required.')
    if not edp_no:
        errors.append('EDP No is required.')
    if not date_of_submission:
        errors.append('Date of Submission is required.')
    if not four_m:
        errors.append('4M is required.')
    if not type_of_defect:
        errors.append('Type of Defect is required.')
    if not defect_reason:
        errors.append('Defect Reason is required.')
    if not operator:
        errors.append('Operator is required.')
    if not processing_result:
        errors.append('Processing Result is required.')
    if not final_result:
        errors.append('Final Result is required.')
    if status not in STATUS_OPTIONS:
        errors.append('Please select a valid Status.')

    if errors:
        for e in errors:
            flash(e, 'error')
        return redirect(url_for('ncr'))

    try:
        as_on_days_val = int(as_on_date_days) if as_on_date_days else 0
    except ValueError:
        as_on_days_val = 0
    try:
        wo_qty_val = int(wo_quantity) if wo_quantity else 0
    except ValueError:
        wo_qty_val = 0
    try:
        prob_qty_val = int(problem_quantity) if problem_quantity else 0
    except ValueError:
        prob_qty_val = 0
    try:
        prob_rate_val = float(problem_rate) if problem_rate else 0.0
    except ValueError:
        prob_rate_val = 0.0

    if not ncr:
        ncr = NCR(
            document_no=document_no,
            date_of_creation=date_of_creation,
            product=product,
            tool_type=tool_type,
            issued_by=issued_by,
            issued_dept=issued_dept,
            wo_no=wo_no,
            edp_no=edp_no,
            date_of_submission=date_of_submission,
            as_on_date_days=as_on_days_val,
            four_m=four_m,
            type_of_defect=type_of_defect,
            defect_reason=defect_reason,
            wo_quantity=wo_qty_val,
            problem_quantity=prob_qty_val,
            problem_rate=prob_rate_val,
            process_generated=process_generated,
            operator=operator,
            processing_result=processing_result,
            final_result=final_result,
            status=status,
            reminder_1=reminder_1,
            completed_date=completed_date,
        )
        db.session.add(ncr)
    else:
        ncr.document_no = document_no
        ncr.date_of_creation = date_of_creation
        ncr.product = product
        ncr.tool_type = tool_type
        ncr.issued_by = issued_by
        ncr.issued_dept = issued_dept
        ncr.wo_no = wo_no
        ncr.edp_no = edp_no
        ncr.date_of_submission = date_of_submission
        ncr.as_on_date_days = as_on_days_val
        ncr.four_m = four_m
        ncr.type_of_defect = type_of_defect
        ncr.defect_reason = defect_reason
        ncr.wo_quantity = wo_qty_val
        ncr.problem_quantity = prob_qty_val
        ncr.problem_rate = prob_rate_val
        ncr.process_generated = process_generated
        ncr.operator = operator
        ncr.processing_result = processing_result
        ncr.final_result = final_result
        ncr.status = status
        ncr.reminder_1 = reminder_1
        ncr.completed_date = completed_date
        ncr.updated_at = datetime.utcnow()

    db.session.commit()
    flash('NCR record saved successfully!', 'success')
    return redirect(url_for('ncr'))


@app.route('/ncr/close/<int:ncr_id>', methods=['POST'])
@login_required
def close_ncr(ncr_id):
    ncr = db.session.get(NCR, ncr_id)
    if ncr:
        ncr.status = 'closed'
        ncr.completed_date = datetime.utcnow().date()
        ncr.updated_at = datetime.utcnow()
        db.session.commit()
        flash('NCR record marked as closed.', 'success')
    else:
        flash('NCR record not found.', 'error')
    return redirect(url_for('ncr'))


@app.route('/ncr/reopen/<int:ncr_id>', methods=['POST'])
@login_required
def reopen_ncr(ncr_id):
    ncr = db.session.get(NCR, ncr_id)
    if ncr:
        ncr.status = 'open'
        ncr.updated_at = datetime.utcnow()
        db.session.commit()
        flash('NCR record reopened.', 'info')
    else:
        flash('NCR record not found.', 'error')
    return redirect(url_for('ncr'))


@app.route('/ncr/delete/<int:ncr_id>', methods=['POST'])
@login_required
def delete_ncr(ncr_id):
    ncr = db.session.get(NCR, ncr_id)
    if ncr:
        db.session.delete(ncr)
        db.session.commit()
        flash('NCR record deleted.', 'info')
    else:
        flash('NCR record not found.', 'error')
    return redirect(url_for('ncr'))


@app.route('/kaizen')
@login_required
def kaizen():
    """Kaizen view - content will be added later."""
    return render_template('kaizen.html', now=datetime.utcnow())


@app.route('/suggestions')
@login_required
def suggestions():
    """Suggestions view - content will be added later."""
    return render_template('suggestions.html', now=datetime.utcnow())


@app.route('/internal-audit/ygct')
@login_required
def ygct_internal_audit():
    """YGCT Internal Audit view."""
    return render_template('ygct_internal_audit.html', now=datetime.utcnow())

@app.route('/internal-audit/ygit')
@login_required
def ygit_internal_audit():
    """YGIT Internal Audit view."""
    return render_template('ygit_internal_audit.html', now=datetime.utcnow())


@app.route('/api/charts')
@login_required
def charts_data():
    audit_type = request.args.get('audit_type', '5S Audit')
    if audit_type not in AUDIT_TYPES:
        audit_type = '5S Audit'
    counts = get_status_counts(audit_type=audit_type)

    base = Audit.query.filter(Audit.audit_type == audit_type)

    plant1_results = db.session.query(
        Audit.responsible_hod,
        db.func.count(Audit.id).label('total'),
        db.func.sum(db.case((Audit.status == 'open', 1), else_=0)).label('open'),
        db.func.sum(db.case((Audit.status == 'closed', 1), else_=0)).label('closed')
    ).filter(Audit.ygct_plant1 != '').filter(Audit.audit_type == audit_type).group_by(Audit.responsible_hod).order_by(Audit.responsible_hod).all()

    plant1_stats = []
    for r in plant1_results:
        plant1_stats.append({
            'hod': r.responsible_hod or 'Unknown',
            'total': r.total or 0,
            'open': r.open or 0,
            'closed': r.closed or 0
        })

    plant2_results = db.session.query(
        Audit.responsible_hod,
        db.func.count(Audit.id).label('total'),
        db.func.sum(db.case((Audit.status == 'open', 1), else_=0)).label('open'),
        db.func.sum(db.case((Audit.status == 'closed', 1), else_=0)).label('closed')
    ).filter(Audit.ygct_plant2 != '').filter(Audit.audit_type == audit_type).group_by(Audit.responsible_hod).order_by(Audit.responsible_hod).all()

    plant2_stats = []
    for r in plant2_results:
        plant2_stats.append({
            'hod': r.responsible_hod or 'Unknown',
            'total': r.total or 0,
            'open': r.open or 0,
            'closed': r.closed or 0
        })

    plant3_results = db.session.query(
        Audit.responsible_hod,
        db.func.count(Audit.id).label('total'),
        db.func.sum(db.case((Audit.status == 'open', 1), else_=0)).label('open'),
        db.func.sum(db.case((Audit.status == 'closed', 1), else_=0)).label('closed')
    ).filter(Audit.ygct_plant3 != '').filter(Audit.audit_type == audit_type).group_by(Audit.responsible_hod).order_by(Audit.responsible_hod).all()

    plant3_stats = []
    for r in plant3_results:
        plant3_stats.append({
            'hod': r.responsible_hod or 'Unknown',
            'total': r.total or 0,
            'open': r.open or 0,
            'closed': r.closed or 0
        })

    today = date.today()
    monthly_results = db.session.query(
        db.func.strftime('%Y-%m', Audit.audit_date).label('month'),
        db.func.count(Audit.id).label('total'),
        db.func.sum(db.case((Audit.status == 'open', 1), else_=0)).label('open'),
        db.func.sum(db.case((Audit.status == 'closed', 1), else_=0)).label('closed')
    ).filter(
        Audit.audit_date >= date(today.year, 1, 1),
        Audit.audit_type == audit_type,
    ).group_by('month').order_by('month').all()

    monthly_map = {}
    for r in monthly_results:
        monthly_map[r.month] = {
            'total': r.total or 0,
            'open': r.open or 0,
            'closed': r.closed or 0
        }

    start_month = date(today.year, 1, 1)
    monthly_stats = []
    current = start_month
    while current <= today:
        month_key = current.strftime('%Y-%m')
        month_label = current.strftime('%b %Y')
        stats = monthly_map.get(month_key, {'total': 0, 'open': 0, 'closed': 0})
        monthly_stats.append({
            'month': month_label,
            'total': stats['total'],
            'open': stats['open'],
            'closed': stats['closed']
        })
        if current.month == 12:
            current = date(current.year + 1, 1, 1)
        else:
            current = date(current.year, current.month + 1, 1)

    return jsonify({
        'counts': counts,
        'plant1_stats': plant1_stats,
        'plant2_stats': plant2_stats,
        'plant3_stats': plant3_stats,
        'monthly_stats': monthly_stats,
    })


@app.route('/api/charts/5s')
@login_required
def five_s_charts_data():
    """Chart data for the 5S Audit dashboard.

    Returns month-wise totals (open/closed/total) and zone-wise totals.
    A `zone` query parameter filters the month-wise series to that zone only.
    """
    selected_zone = request.args.get('zone', '').strip()

    base = FiveSAudit.query

    # Zone-wise totals (always unfiltered so the selector shows every zone)
    zone_results = db.session.query(
        FiveSAudit.zone,
        db.func.count(FiveSAudit.id).label('total'),
        db.func.sum(db.case((FiveSAudit.percentage >= 70, 1), else_=0)).label('good'),
        db.func.sum(db.case((FiveSAudit.percentage < 70, 1), else_=0)).label('poor'),
    ).group_by(FiveSAudit.zone).order_by(FiveSAudit.zone).all()

    zone_stats = []
    for r in zone_results:
        zone_stats.append({
            'zone': r.zone or 'Unknown',
            'total': r.total or 0,
            'good': r.good or 0,
            'poor': r.poor or 0,
        })

    # Month-wise totals for the current year
    today = date.today()
    month_query = db.session.query(
        db.func.strftime('%Y-%m', FiveSAudit.audit_date).label('month'),
        db.func.count(FiveSAudit.id).label('total'),
        db.func.sum(db.case((FiveSAudit.percentage >= 70, 1), else_=0)).label('good'),
        db.func.sum(db.case((FiveSAudit.percentage < 70, 1), else_=0)).label('poor'),
    ).filter(FiveSAudit.audit_date >= date(today.year, 1, 1))

    if selected_zone:
        month_query = month_query.filter(FiveSAudit.zone == selected_zone)

    month_results = month_query.group_by('month').order_by('month').all()

    monthly_map = {}
    for r in month_results:
        monthly_map[r.month] = {
            'total': r.total or 0,
            'good': r.good or 0,
            'poor': r.poor or 0,
        }

    monthly_stats = []
    current = date(today.year, 1, 1)
    while current <= today:
        month_key = current.strftime('%Y-%m')
        month_label = current.strftime('%b %Y')
        stats = monthly_map.get(month_key, {'total': 0, 'good': 0, 'poor': 0})
        monthly_stats.append({
            'month': month_label,
            'total': stats['total'],
            'good': stats['good'],
            'poor': stats['poor'],
        })
        if current.month == 12:
            current = date(current.year + 1, 1, 1)
        else:
            current = date(current.year, current.month + 1, 1)

    return jsonify({
        'zone_stats': zone_stats,
        'monthly_stats': monthly_stats,
        'selected_zone': selected_zone,
    })


@app.route('/rules')
@login_required
def rules():
    all_rules = Rule.query.order_by(Rule.created_at.desc()).all()
    return render_template('rules.html', rules=all_rules)


@app.route('/rules/add', methods=['GET', 'POST'])
@login_required
def add_rule():
    if request.method == 'POST':
        rule_name = request.form.get('rule_name', '').strip()
        item = request.form.get('item', '').strip()
        required_location = request.form.get('required_location', '').strip()
        description = request.form.get('description', '').strip()

        errors = []
        if not rule_name:
            errors.append('Rule Name is required.')
        if not item:
            errors.append('Item is required.')
        if not required_location:
            errors.append('Required Location is required.')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('rule_form.html', form=request.form)

        attachment_file = request.files.get('file_attachment')
        attachment_name = save_attachment(attachment_file)

        rule = Rule(
            rule_name=rule_name,
            item=item,
            required_location=required_location,
            description=description,
            file_attachment=attachment_name,
        )
        db.session.add(rule)
        db.session.commit()
        flash('Rule created successfully!', 'success')
        return redirect(url_for('rules'))

    return render_template('rule_form.html')


@app.route('/rules/edit/<int:rule_id>', methods=['GET', 'POST'])
@login_required
def edit_rule(rule_id):
    rule = db.session.get(Rule, rule_id)
    if not rule:
        flash('Rule not found.', 'error')
        return redirect(url_for('rules'))

    if request.method == 'POST':
        rule.rule_name = request.form.get('rule_name', '').strip()
        rule.item = request.form.get('item', '').strip()
        rule.required_location = request.form.get('required_location', '').strip()
        rule.description = request.form.get('description', '').strip()
        rule.updated_at = datetime.utcnow()

        errors = []
        if not rule.rule_name:
            errors.append('Rule Name is required.')
        if not rule.item:
            errors.append('Item is required.')
        if not rule.required_location:
            errors.append('Required Location is required.')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('rule_form.html', rule=rule, form=request.form)

        attachment_file = request.files.get('file_attachment')
        if attachment_file and attachment_file.filename:
            old_attachment = rule.file_attachment
            if old_attachment:
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_attachment)
                try:
                    os.remove(old_path)
                except OSError:
                    pass
            new_attachment = save_attachment(attachment_file)
            if new_attachment:
                rule.file_attachment = new_attachment

        db.session.commit()
        flash('Rule updated successfully!', 'success')
        return redirect(url_for('rules'))

    return render_template('rule_form.html', rule=rule)


@app.route('/rules/delete/<int:rule_id>', methods=['POST'])
@login_required
def delete_rule(rule_id):
    rule = db.session.get(Rule, rule_id)
    if rule:
        db.session.delete(rule)
        db.session.commit()
        flash('Rule deleted.', 'info')
    return redirect(url_for('rules'))


ALLOWED_PREVIEW_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp'}


@app.route('/rules/attachment/<int:rule_id>')
@login_required
def rule_attachment(rule_id):
    rule = db.session.get(Rule, rule_id)
    if not rule or not rule.file_attachment:
        flash('Attachment not found.', 'error')
        return redirect(url_for('rules'))
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], rule.file_attachment)
    if not os.path.exists(filepath):
        flash('Attachment file is missing on disk.', 'error')
        return redirect(url_for('rules'))
    ext = rule.file_attachment.rsplit('.', 1)[1].lower() if '.' in rule.file_attachment else ''
    mimetype = {
        'pdf': 'application/pdf',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'doc': 'application/msword',
        'txt': 'text/plain',
        'csv': 'text/csv',
        'json': 'application/json',
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'gif': 'image/gif',
        'webp': 'image/webp',
    }.get(ext, 'application/octet-stream')
    return send_file(filepath, as_attachment=False, mimetype=mimetype)


@app.route('/rules/attachment/download/<int:rule_id>')
@login_required
def rule_attachment_download(rule_id):
    rule = db.session.get(Rule, rule_id)
    if not rule or not rule.file_attachment:
        flash('Attachment not found.', 'error')
        return redirect(url_for('rules'))
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], rule.file_attachment)
    if not os.path.exists(filepath):
        flash('Attachment file is missing on disk.', 'error')
        return redirect(url_for('rules'))
    return send_file(filepath, as_attachment=True, download_name=rule.file_attachment)


@app.route('/rules/upload', methods=['GET', 'POST'])
@login_required
def upload_rules():
    # Only allow admin users to upload rules
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('rules'))
    
    if request.method == 'POST':
        if 'rule_file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        
        file = request.files['rule_file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        
        if file and allowed_rule_file(file.filename):
            filename = save_rule_upload(file)
            if filename:
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    rules_created = 0
                    errors = []
                    
                    # Parse CSV file
                    if filename.endswith('.csv'):
                        import csv
                        with open(filepath, 'r', encoding='utf-8') as f:
                            reader = csv.DictReader(f)
                            for row_num, row in enumerate(reader, start=2):  # start at 2 since header is row 1
                                try:
                                    rule_name = row.get('rule_name', '').strip()
                                    item = row.get('item', '').strip()
                                    required_location = row.get('required_location', '').strip()
                                    description = row.get('description', '').strip()
                                    
                                    if not rule_name:
                                        errors.append(f'Row {row_num}: Rule Name is required.')
                                        continue
                                    if not item:
                                        errors.append(f'Row {row_num}: Item is required.')
                                        continue
                                    if not required_location:
                                        errors.append(f'Row {row_num}: Required Location is required.')
                                        continue
                                    
                                    rule = Rule(
                                        rule_name=rule_name,
                                        item=item,
                                        required_location=required_location,
                                        description=description,
                                    )
                                    db.session.add(rule)
                                    rules_created += 1
                                except Exception as e:
                                    errors.append(f'Row {row_num}: Error processing row - {str(e)}')
                    
                    # Parse JSON file
                    elif filename.endswith('.json'):
                        import json
                        with open(filepath, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            if not isinstance(data, list):
                                errors.append('JSON file must contain an array of rule objects')
                            else:
                                for index, item in enumerate(data):
                                    try:
                                        rule_name = item.get('rule_name', '').strip()
                                        item_name = item.get('item', '').strip()
                                        required_location = item.get('required_location', '').strip()
                                        description = item.get('description', '').strip()
                                        
                                        if not rule_name:
                                            errors.append(f'Item {index + 1}: Rule Name is required.')
                                            continue
                                        if not item_name:
                                            errors.append(f'Item {index + 1}: Item is required.')
                                            continue
                                        if not required_location:
                                            errors.append(f'Item {index + 1}: Required Location is required.')
                                            continue
                                            
                                        rule = Rule(
                                            rule_name=rule_name,
                                            item=item_name,
                                            required_location=required_location,
                                            description=description,
                                        )
                                        db.session.add(rule)
                                        rules_created += 1
                                    except Exception as e:
                                        errors.append(f'Item {index + 1}: Error processing item - {str(e)}')
                    
                    # Parse TXT file (simple format: rule_name|item|required_location|description per line)
                    elif filename.endswith('.txt'):
                        with open(filepath, 'r', encoding='utf-8') as f:
                            for line_num, line in enumerate(f, start=1):
                                line = line.strip()
                                if not line:
                                    continue
                                parts = line.split('|')
                                if len(parts) < 3:
                                    errors.append(f'Line {line_num}: Invalid format. Expected: rule_name|item|required_location|description')
                                    continue
                                
                                rule_name = parts[0].strip()
                                item_name = parts[1].strip()
                                required_location = parts[2].strip()
                                description = parts[3].strip() if len(parts) > 3 else ''
                                
                                if not rule_name:
                                    errors.append(f'Line {line_num}: Rule Name is required.')
                                    continue
                                if not item_name:
                                    errors.append(f'Line {line_num}: Item is required.')
                                    continue
                                if not required_location:
                                    errors.append(f'Line {line_num}: Required Location is required.')
                                    continue
                                
                                rule = Rule(
                                    rule_name=rule_name,
                                    item=item_name,
                                    required_location=required_location,
                                    description=description,
                                )
                                db.session.add(rule)
                                rules_created += 1
                    
                    if errors:
                        for error in errors[:5]:  # Show first 5 errors
                            flash(error, 'error')
                        if len(errors) > 5:
                            flash(f'And {len(errors) - 5} more errors...', 'error')
                        db.session.rollback()
                    else:
                        db.session.commit()
                        flash(f'Successfully created {rules_created} rules from {filename}', 'success')
                        return redirect(url_for('rules'))
                        
                except Exception as e:
                    flash(f'Error processing file: {str(e)}', 'error')
                    db.session.rollback()
                finally:
                    # Clean up uploaded file
                    try:
                        os.remove(filepath)
                    except:
                        pass
            else:
                flash('Invalid file type', 'error')
        else:
            flash('Allowed file types are: csv, json, txt', 'error')
        
        return redirect(request.url)
    
    return render_template('rule_upload.html')


@app.route('/audits')
@login_required
def audits():
    all_audits = []
    return render_template(
        'audits.html',
        audits=all_audits,
        plants=PLANTS,
        zones=ZONES,
        zonal_leaders=ZONAL_LEADERS,
        audit_types=AUDIT_TYPES,
    )


def _audit_export_rows(hod_query):
    query = Audit.query.order_by(Audit.created_at.desc())
    if hod_query:
        query = query.filter(Audit.responsible_hod.ilike(f'%{hod_query}%'))
    return query.all()


def _audit_export_columns(audit):
    return [
        audit.id,
        audit.audit_date.strftime('%d-%m-%Y') if audit.audit_date else '',
        audit.plant or '',
        audit.zone or '',
        audit.zonal_leader or '',
        audit.audit_type or '',
        audit.nc_category or '',
        audit.description or '',
        audit.action_taken_details or '',
        audit.responsible_hod or '',
        audit.responsible_email or '',
        audit.target_date.strftime('%d-%m-%Y') if audit.target_date else '',
        (audit.status or '').capitalize(),
    ]


EXPORT_HEADERS = [
    'ID', 'Audit Date', 'Plant', 'Zone', 'Zonal Leader',
    'Audit Type', 'NC Category', 'Description of NC', 'Action Taken',
    'Responsible HOD', 'Responsible Email', 'Target Date', 'Status',
]


@app.route('/audits/export/pdf')
@login_required
def export_audits_pdf():
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.enums import TA_CENTER, TA_LEFT

    hod_query = request.args.get('hod', '').strip()
    audits = _audit_export_rows(hod_query)

    buffer = BytesIO()
    page_width, page_height = landscape(A4)

    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=28 * mm,
        bottomMargin=18 * mm,
    )

    logo_path = os.path.join(app.static_folder, 'images', 'yg1_images.png')
    export_time = datetime.utcnow().strftime('%d-%m-%Y %H:%M')

    def add_header_footer(canvas, doc_obj):
        canvas.saveState()
        canvas.setFillColor(colors.white)
        canvas.rect(0, page_height - 28 * mm, page_width, 28 * mm, fill=1)
        canvas.setFillColor(colors.HexColor('#2563eb'))
        canvas.setFont('Helvetica-Bold', 15)
        canvas.drawString(doc_obj.leftMargin, page_height - 16 * mm, 'YG1')
        canvas.setFillColor(colors.HexColor('#f5c520'))
        canvas.drawString(doc_obj.leftMargin + 34, page_height - 16 * mm, 'Monitoring')
        canvas.setFillColor(colors.HexColor('#64748b'))
        canvas.setFont('Helvetica', 8)
        filter_note = f'Filtered by HOD: {hod_query}' if hod_query else 'All Records'
        canvas.drawString(doc_obj.leftMargin, page_height - 23, filter_note)
        canvas.setFillColor(colors.HexColor('#94a3b8'))
        canvas.setFont('Helvetica', 7)
        canvas.drawRightString(page_width - doc_obj.rightMargin, page_height - 23, f'Records: {len(audits)}')
        if os.path.exists(logo_path):
            canvas.drawImage(
                logo_path, page_width - doc_obj.rightMargin - 24, page_height - 18 * mm,
                width=24, height=24, preserveAspectRatio=True, mask='auto',
            )
        canvas.setStrokeColor(colors.HexColor('#e2e8f0'))
        canvas.setLineWidth(0.5)
        canvas.line(doc_obj.leftMargin, 18 * mm, page_width - doc_obj.rightMargin, 18 * mm)
        canvas.setFillColor(colors.HexColor('#94a3b8'))
        canvas.setFont('Helvetica', 8)
        canvas.drawString(doc_obj.leftMargin, 8, f'Exported on {export_time}')
        canvas.drawRightString(page_width - doc_obj.rightMargin, 8, f'Page {canvas.getPageNumber()}')
        canvas.restoreState()

    styles = getSampleStyleSheet()
    summary_style = ParagraphStyle(
        'Summary',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=12,
    )

    elements = []
    filter_str = f' (Filtered by HOD: {hod_query})' if hod_query else ''
    elements.append(Paragraph(
        f'<b style="color:#1e293b; font-size:18px;">YG1 Audit Records{filter_str}</b>',
        ParagraphStyle('H1', parent=styles['Title'], alignment=TA_CENTER, spaceAfter=4),
    ))
    elements.append(Paragraph(
        f'{export_time} &nbsp;|&nbsp; Total Records: {len(audits)}',
        summary_style,
    ))

    cell_style = ParagraphStyle(
        'Cell',
        parent=styles['Normal'],
        fontSize=7,
        leading=9,
        alignment=TA_LEFT,
        textColor=colors.HexColor('#334155'),
        wordWrap='LTR',
    )
    header_style = ParagraphStyle(
        'Header',
        parent=cell_style,
        fontSize=7,
        fontName='Helvetica-Bold',
        textColor=colors.white,
        alignment=TA_CENTER,
        wordWrap='LTR',
    )

    pdf_headers = ['S.No'] + EXPORT_HEADERS[1:]
    table_data = [[Paragraph(h, header_style) for h in pdf_headers]]
    for serial_no, audit in enumerate(audits, start=1):
        cols = _audit_export_columns(audit)
        cols[0] = serial_no
        table_data.append([Paragraph(str(c), cell_style) for c in cols])

    col_widths = [
        12 * mm, 20 * mm, 18 * mm, 18 * mm, 22 * mm, 19 * mm,
        34 * mm, 34 * mm, 25 * mm, 33 * mm, 20 * mm, 16 * mm,
    ]
    table = Table(table_data, colWidths=col_widths, repeatRows=1, hAlign='LEFT')
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(table)

    doc.build(elements, onFirstPage=add_header_footer, onLaterPages=add_header_footer)

    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'yg1_audits_{datetime.utcnow().strftime("%Y%m%d_%H%M")}.pdf',
        mimetype='application/pdf',
    )


@app.route('/audits/export/excel')
@login_required
def export_audits_excel():
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

    hod_query = request.args.get('hod', '').strip()
    audits = _audit_export_rows(hod_query)

    wb = Workbook()
    ws = wb.active
    ws.title = 'Audit Records'

    header_font = Font(bold=True, color='FFFFFF', size=11)
    header_fill = PatternFill(start_color='2563EB', end_color='2563EB', fill_type='solid')
    thin_border = Border(
        left=Side(style='thin'), right=Side(style='thin'),
        top=Side(style='thin'), bottom=Side(style='thin'),
    )
    wrap_alignment = Alignment(wrap_text=True, vertical='top', horizontal='left')

    ws.append(EXPORT_HEADERS)
    for cell in ws[1]:
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = wrap_alignment
        cell.border = thin_border

    for audit in audits:
        row = _audit_export_columns(audit)
        ws.append(row)
        for cell in ws[ws.max_row]:
            cell.border = thin_border
            cell.alignment = wrap_alignment

    column_widths = [10, 14, 14, 14, 16, 14, 30, 26, 20, 24, 14, 12, 14]
    for col_idx, width in enumerate(column_widths, 1):
        ws.column_dimensions[ws.cell(row=1, column=col_idx).column_letter].width = width

    buffer = BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'yg1_audits_{datetime.utcnow().strftime("%Y%m%d_%H%M")}.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    )


@app.route('/audits/save', methods=['POST'])
@login_required
def save_audit():
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    audit_id = request.form.get('audit_id', type=int)
    audit = db.session.get(Audit, audit_id) if audit_id else None
    if audit_id and not audit:
        if is_ajax:
            return jsonify({'ok': False, 'message': 'Audit record not found.'}), 404
        flash('Audit record not found.', 'error')
        return redirect(url_for('audits'))

    plant = request.form.get('plant', '').strip()
    zone = request.form.get('zone', '').strip()
    zonal_leader = request.form.get('zonal_leader', '').strip()
    nc_category = request.form.get('nc_category', '').strip()
    description = request.form.get('description', '').strip()
    action_taken_details = request.form.get('action_taken_details', '').strip()
    responsible_hod = request.form.get('responsible_hod', '').strip()
    responsible_email = request.form.get('responsible_email', '').strip()
    audit_date = parse_date(request.form.get('audit_date', ''))
    target_date = parse_date(request.form.get('target_date', ''))
    status = request.form.get('status', 'open')
    audit_type = request.form.get('audit_type', '5S Audit')

    errors = []
    if not audit_date:
        errors.append('Audit Date is required.')

    current_plant = audit.plant if audit else ''
    current_zone = audit.zone if audit else ''
    current_leader = audit.zonal_leader if audit else ''
    current_audit_type = audit.audit_type if audit else '5S Audit'
    dropdowns = (
        ('Plant', plant, PLANTS, current_plant),
        ('Zone', zone, ZONES, current_zone),
        ('Zonal Leader', zonal_leader, ZONAL_LEADERS, current_leader),
        ('Audit Type', audit_type, AUDIT_TYPES, current_audit_type),
    )
    for label, value, options, current in dropdowns:
        if value not in options and value != current:
            errors.append(f'Please select a {label} from the dropdown.')

    if not nc_category:
        errors.append('NC Category is required.')
    if not description:
        errors.append('Description of Non Conformity is required.')
    if not responsible_hod:
        errors.append('Responsible HOD is required.')
    if not responsible_email:
        errors.append('Responsible Email is required.')
    if status not in STATUS_OPTIONS:
        errors.append('Please select a valid Status.')

    if errors:
        if is_ajax:
            return jsonify({'ok': False, 'errors': errors}), 400
        for e in errors:
            flash(e, 'error')
        return redirect(url_for('audits'))

    before_file = request.files.get('before_image')
    after_file = request.files.get('after_image')

    if not audit:
        audit = Audit(audit_date=audit_date, zone=zone, zonal_leader=zonal_leader)
        db.session.add(audit)
    else:
        audit.audit_date = audit_date
        audit.updated_at = datetime.utcnow()

    audit.plant = plant
    audit.zone = zone
    audit.zonal_leader = zonal_leader
    audit.nc_category = nc_category
    audit.description = description
    audit.action_taken_details = action_taken_details
    audit.responsible_hod = responsible_hod
    audit.responsible_email = responsible_email
    audit.target_date = target_date
    audit.status = status
    audit.audit_type = audit_type
    if before_file and before_file.filename:
        audit.before_image = save_upload(before_file) or audit.before_image
    if after_file and after_file.filename:
        uploaded_after = save_upload(after_file)
        if uploaded_after:
            audit.after_image = uploaded_after
            audit.status = 'closed'

    db.session.commit()

    if not audit_id:
        create_audit_alert(audit)
        msg = 'Audit record saved successfully!'
    else:
        msg = 'Audit record updated successfully!'

    if is_ajax:
        return jsonify({'ok': True, 'message': msg, 'id': audit.id})
    flash(msg, 'success')
    return redirect(url_for('hod_audit_summary') if audit_type == 'HOD Audit' else url_for('five_s_audit_summary'))


@app.route('/audits/add')
@login_required
def add_audit():
    return redirect(url_for('audits'))


@app.route('/audits/edit/<int:audit_id>')
@login_required
def edit_audit(audit_id):
    return redirect(url_for('audits'))



@app.route('/audits/close/<int:audit_id>', methods=['POST'])
@login_required
def close_audit(audit_id):
    audit = db.session.get(Audit, audit_id)
    if audit:
        audit.status = 'closed'
        audit.updated_at = datetime.utcnow()
        db.session.commit()
        flash('Audit record marked as closed.', 'success')
    else:
        flash('Audit record not found.', 'error')
    return redirect(url_for('audits'))


@app.route('/audits/reopen/<int:audit_id>', methods=['POST'])
@login_required
def reopen_audit(audit_id):
    audit = db.session.get(Audit, audit_id)
    if audit:
        audit.status = 'open'
        audit.updated_at = datetime.utcnow()
        db.session.commit()
        flash('Audit record reopened.', 'info')
    else:
        flash('Audit record not found.', 'error')
    return redirect(url_for('audits'))


@app.route('/audits/delete/<int:audit_id>', methods=['POST'])
@login_required
def delete_audit(audit_id):
    audit = db.session.get(Audit, audit_id)
    if audit:
        db.session.delete(audit)
        db.session.commit()
        flash('Audit record deleted.', 'info')
    else:
        flash('Audit record not found.', 'error')
    return redirect(url_for('audits'))


@app.route('/hod-summary')
@login_required
def hod_summary():
    hod_data = db.session.query(
        Audit.responsible_hod,
        db.func.count(Audit.id).label('total'),
        db.func.sum(db.case((Audit.status == 'open', 1), else_=0)).label('open_count'),
        db.func.sum(db.case((Audit.status == 'closed', 1), else_=0)).label('closed_count')
    ).group_by(Audit.responsible_hod).order_by(Audit.responsible_hod).all()
    return render_template('hod_summary.html', hod_data=hod_data)


@app.route('/hod-summary/<path:hod>')
@login_required
def hod_detail(hod):
    selected_date_str = request.args.get('date')
    selected_date = parse_date(selected_date_str)

    base_query = Audit.query.filter(
        Audit.responsible_hod == hod
    ).order_by(Audit.audit_date.desc(), Audit.created_at.desc())

    available_dates = db.session.query(Audit.audit_date).filter(
        Audit.responsible_hod == hod
    ).distinct().order_by(Audit.audit_date.desc()).all()
    available_dates = [d.audit_date for d in available_dates]

    if selected_date:
        audits = base_query.filter(Audit.audit_date == selected_date).all()
    else:
        audits = base_query.all()

    return render_template(
        'hod_detail.html',
        hod=hod,
        audits=audits,
        available_dates=available_dates,
        selected_date=selected_date,
    )


def create_audit_alert(audit):
    subject = f"New Audit Alert: {audit.nc_category} - {audit.plant}"
    plant_info = f"Plant: {audit.plant}\nZone: {audit.zone}"
    body_text = (
        f"A new audit record has been created.\n\n"
        f"Audit Date: {audit.audit_date}\n"
        f"{plant_info}\n"
        f"Zonal Leader: {audit.zonal_leader}\n"
        f"NC Category: {audit.nc_category}\n"
        f"Description: {audit.description}\n"
        f"Responsible HOD: {audit.responsible_hod}\n"
        f"Target Date: {audit.target_date or 'Not set'}\n"
        f"Status: {audit.status}\n\n"
        f"Please take necessary action."
    )
    body_html = (
        f"<h3>New Audit Alert: {audit.nc_category}</h3>"
        f"<p><strong>Plant:</strong> {audit.plant}</p>"
        f"<p><strong>Zone:</strong> {audit.zone}</p>"
        f"<p><strong>Audit Date:</strong> {audit.audit_date}</p>"
        f"<p><strong>Zonal Leader:</strong> {audit.zonal_leader}</p>"
        f"<p><strong>NC Category:</strong> {audit.nc_category}</p>"
        f"<p><strong>Description:</strong> {audit.description}</p>"
        f"<p><strong>Responsible HOD:</strong> {audit.responsible_hod}</p>"
        f"<p><strong>Target Date:</strong> {audit.target_date or 'Not set'}</p>"
        f"<p><strong>Status:</strong> {audit.status}</p>"
        f"<p>Please take necessary action.</p>"
    )

    alert = Alert(
        audit_id=audit.id,
        subject=subject,
        message=body_text,
        responsible_email=audit.responsible_email,
        sent_at=datetime.utcnow(),
    )
    db.session.add(alert)
    db.session.commit()

    sent, error_msg = send_email(audit.responsible_email, subject, body_text, body_html)
    if sent:
        flash(f"Alert email sent to {audit.responsible_email}.", 'success')
    else:
        flash(f"Email failed: {error_msg}", 'error')

    return alert


@app.route('/mail-logs')
@login_required
def mail_logs():
    logs = MailLog.query.order_by(MailLog.sent_at.desc()).limit(100).all()
    return render_template('mail_logs.html', logs=logs)


@app.route('/alerts')
@login_required
def alerts():
    all_alerts = Alert.query.order_by(Alert.sent_at.desc()).all()
    return render_template('alerts.html', alerts=all_alerts)


@app.route('/alerts/acknowledge/<int:alert_id>', methods=['POST'])
@login_required
def acknowledge_alert(alert_id):
    alert = db.session.get(Alert, alert_id)
    if alert:
        alert.acknowledged = True
        db.session.commit()
        flash('Alert acknowledged.', 'success')
    else:
        flash('Alert not found.', 'error')
    return redirect(url_for('hod_audit'))


@app.route('/alerts/resend/<int:alert_id>', methods=['POST'])
@login_required
def resend_alert(alert_id):
    alert = db.session.get(Alert, alert_id)
    if alert:
        audit = db.session.get(Audit, alert.audit_id)
        if audit:
            sent, error_msg = send_email(
                alert.responsible_email,
                alert.subject,
                alert.message,
                f"<h3>{alert.subject}</h3><p>{alert.message.replace(chr(10), '<br>')}</p>"
            )
            if sent:
                flash(f"Alert resent to {alert.responsible_email}.", 'success')
            else:
                flash(f"Email failed: {error_msg}", 'error')
        else:
            flash('Associated audit not found.', 'error')
    else:
        flash('Alert not found.', 'error')
    return redirect(url_for('alerts'))


@app.route('/test-email')
@login_required
def test_email():
    try:
        resend.api_key = os.getenv('RESEND_API_KEY')

        if not resend.api_key:
            return 'RESEND_API_KEY is missing in .env file', 500

        recipient = request.args.get('email', '').strip()

        if not recipient:
            return 'Usage: /test-email?email=your@email.com', 400

        params = {
            "from": os.getenv('RESEND_FROM_EMAIL', 'onboarding@resend.dev'),
            "to": [recipient],
            "subject": "YG1 Monitoring - Test Email",
            "html": """
                <h2>YG1 Monitoring System</h2>
                <p>Hello,</p>
                <p>This is a test email from the YG1 Monitoring System.</p>
                <p>Resend email integration is working successfully.</p>
            """
        }

        response = resend.Emails.send(params)

        return f"Email sent successfully to {recipient}! Response: {response}", 200

    except Exception as e:
        return f"Email failed: {str(e)}", 500


def _initialize_app():
    """Create tables, run migrations, and seed the default admin user.

    Runs on import so the DB is ready under gunicorn/WSGI too, not only
    when launched with `python app.py`."""
    with app.app_context():
        db.create_all()
        run_migrations()

        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@company.com', role='admin')
            admin.set_password('Admin@123')
            db.session.add(admin)
            db.session.commit()
            print('[OK] Default admin created: username="admin" password="Admin@123"')


_initialize_app()


if __name__ == '__main__':
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        _start_alert_reminder_scheduler()
        print('[OK] Alert reminder scheduler started (checks every %ds)' % REMINDER_CHECK_INTERVAL)

    app.run(debug=True)
    
    
