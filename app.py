import os
import smtplib
import resend
import ssl
import time
import uuid
from datetime import datetime, date, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify, abort
)
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from dotenv import load_dotenv

from extensions import db
from models import User, Rule, Audit, Alert, MailLog
from sqlalchemy import case


load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=12)

IDLE_TIMEOUT_SECONDS = 30 * 60

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

PLANTS = ['Plant 1', 'Plant 2', 'Plant 3']

# Zone names can be replaced here once the final list is confirmed.
ZONES = [f'Zone {i}' for i in range(1, 21)]

# Zonal leader names can be replaced here once the final list is confirmed.
ZONAL_LEADERS = [f'Zonal Leader {i}' for i in range(1, 11)]

STATUS_OPTIONS = ['open', 'closed']


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_upload(file_storage):
    if not file_storage or file_storage.filename == '':
        return None
    if not allowed_file(file_storage.filename):
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
    smtp_host = os.getenv('SMTP_HOST', '').strip()
    smtp_port = int(os.getenv('SMTP_PORT', '587') or '587')
    smtp_user = os.getenv('SMTP_USERNAME', '').strip()
    smtp_pass = os.getenv('SMTP_PASSWORD', '').strip()
    from_email = os.getenv('ALERT_FROM_EMAIL', '').strip() or smtp_user

    log_entry = MailLog(
        recipient=to_email,
        subject=subject,
        body=body_text,
        status='failed',
        error=None,
    )

    if not smtp_host or not smtp_user or not smtp_pass:
        error_msg = 'SMTP not configured. Set SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD in .env'
        log_entry.error = error_msg
        db.session.add(log_entry)
        db.session.commit()
        print(f"[EMAIL LOGGED] To: {to_email} | Subject: {subject}")
        print(f"  Body: {body_text}")
        return False, error_msg

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email
    msg.attach(MIMEText(body_text, 'plain'))
    if body_html:
        msg.attach(MIMEText(body_html, 'html'))

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls(context=context)
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_email, to_email, msg.as_string())
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


def get_status_counts():
    total = Audit.query.count()
    open_count = Audit.query.filter_by(status='open').count()
    closed_count = Audit.query.filter_by(status='closed').count()
    return {
        'total': total,
        'open': open_count,
        'closed': closed_count,
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
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        user_id = request.form.get('id', '').strip()
        password = request.form.get('password', '')

        if not user_id or not password:
            flash('Please enter both ID and password.', 'error')
            return render_template('login.html')

        if user_id != 'arun123' or password != '2av12me003':
            flash('Invalid ID or password.', 'error')
            return render_template('login.html')

        user = User.query.first()
        if not user:
            flash('No user account found. Contact administrator.', 'error')
            return render_template('login.html')

        if not user.is_active:
            flash('Your account has been deactivated. Contact an administrator.', 'error')
            return render_template('login.html')

        login_user(user, remember=request.form.get('remember') == 'on')
        session['last_login'] = datetime.utcnow().isoformat()
        session['last_seen'] = time.time()
        flash(f'Welcome back, {user.username}!', 'success')

        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('dashboard'))

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
    audits = Audit.query.order_by(Audit.created_at.desc()).limit(10).all()
    alerts = Alert.query.order_by(Alert.sent_at.desc()).limit(10).all()
    counts = get_status_counts()

    return render_template(
        'dashboard.html',
        audits=audits,
        alerts=alerts,
        counts=counts,
        now=datetime.utcnow()
    )


@app.route('/api/charts')
@login_required
def charts_data():
    counts = get_status_counts()

    today = date.today()

    plant1_results = db.session.query(
        Audit.responsible_hod,
        db.func.count(Audit.id).label('total'),
        db.func.sum(db.case((Audit.status == 'open', 1), else_=0)).label('open'),
        db.func.sum(db.case((Audit.status == 'closed', 1), else_=0)).label('closed')
    ).filter(Audit.ygct_plant1 != '').group_by(Audit.responsible_hod).order_by(Audit.responsible_hod).all()

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
    ).filter(Audit.ygct_plant2 != '').group_by(Audit.responsible_hod).order_by(Audit.responsible_hod).all()

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
    ).filter(Audit.ygct_plant3 != '').group_by(Audit.responsible_hod).order_by(Audit.responsible_hod).all()

    plant3_stats = []
    for r in plant3_results:
        plant3_stats.append({
            'hod': r.responsible_hod or 'Unknown',
            'total': r.total or 0,
            'open': r.open or 0,
            'closed': r.closed or 0
        })

    monthly_results = db.session.query(
        db.func.strftime('%Y-%m', Audit.audit_date).label('month'),
        db.func.count(Audit.id).label('total'),
        db.func.sum(db.case((Audit.status == 'open', 1), else_=0)).label('open'),
        db.func.sum(db.case((Audit.status == 'closed', 1), else_=0)).label('closed')
    ).filter(
        Audit.audit_date >= date(today.year, 1, 1)
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

        rule = Rule(
            rule_name=rule_name,
            item=item,
            required_location=required_location,
            description=description,
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


@app.route('/audits')
@login_required
def audits():
    hod_query = request.args.get('hod', '').strip()
    query = Audit.query.order_by(Audit.created_at.desc())
    if hod_query:
        query = query.filter(Audit.responsible_hod.ilike(f'%{hod_query}%'))
    all_audits = query.all()
    return render_template(
        'audits.html',
        audits=all_audits,
        plants=PLANTS,
        zones=ZONES,
        zonal_leaders=ZONAL_LEADERS,
    )


@app.route('/audits/save', methods=['POST'])
@login_required
def save_audit():
    audit_id = request.form.get('audit_id', type=int)
    audit = db.session.get(Audit, audit_id) if audit_id else None
    if audit_id and not audit:
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

    errors = []
    if not audit_date:
        errors.append('Audit Date is required.')

    current_plant = audit.plant if audit else ''
    current_zone = audit.zone if audit else ''
    current_leader = audit.zonal_leader if audit else ''
    dropdowns = (
        ('Plant', plant, PLANTS, current_plant),
        ('Zone', zone, ZONES, current_zone),
        ('Zonal Leader', zonal_leader, ZONAL_LEADERS, current_leader),
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
        flash('Audit record created successfully!', 'success')
    else:
        flash('Audit record updated successfully!', 'success')

    return redirect(url_for('audits'))


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


@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash('Access denied. Administrators only.', 'error')
        return redirect(url_for('dashboard'))
    all_users = User.query.all()
    return render_template('users.html', users=all_users)


@app.route('/users/deactivate/<int:user_id>', methods=['POST'])
@login_required
def deactivate_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    if user_id == current_user.id:
        flash('You cannot deactivate your own account.', 'error')
        return redirect(url_for('users'))
    user = db.session.get(User, user_id)
    if user:
        user.is_active = not user.is_active
        db.session.commit()
        action = 'deactivated' if not user.is_active else 'activated'
        flash(f'User {user.username} {action}.', 'info')
    return redirect(url_for('users'))


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
    return redirect(url_for('dashboard'))


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


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        run_migrations()

        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@company.com', role='admin')
            admin.set_password('Admin@123')
            db.session.add(admin)
            db.session.commit()
            print('[OK] Default admin created: username="admin" password="Admin@123"')

    app.run(debug=True)
    
    
