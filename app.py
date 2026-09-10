import os
import smtplib
import ssl
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

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}


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
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except (ValueError, TypeError):
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


def get_status_counts():
    total = Audit.query.count()
    open_count = Audit.query.filter_by(status='open').count()
    closed_count = Audit.query.filter_by(status='closed').count()
    return {
        'total': total,
        'open': open_count,
        'closed': closed_count,
    }


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
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash('Invalid username or password.', 'error')
            return render_template('login.html')

        if not user.is_active:
            flash('Your account has been deactivated. Contact an administrator.', 'error')
            return render_template('login.html')

        login_user(user, remember=request.form.get('remember') == 'on')
        session['last_login'] = datetime.utcnow().isoformat()
        flash(f'Welcome back, {user.username}!', 'success')

        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if not os.getenv('ALLOW_REGISTRATION', 'true').lower() == 'true':
        flash('Registration is disabled by the administrator.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'coordinator')

        errors = []
        if len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if '@' not in email or '.' not in email:
            errors.append('Please enter a valid email address.')
        if len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        if password != confirm_password:
            errors.append('Passwords do not match.')
        if User.query.filter_by(username=username).first():
            errors.append('Username already taken.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')
        if role not in ('admin', 'coordinator'):
            role = 'coordinator'

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('register.html', form=request.form)

        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
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

    current_month_start = date(today.year, today.month, 1)
    current_month_end = date(today.year, today.month + 1, 1) if today.month < 12 else date(today.year + 1, 1, 1)
    current_month_results = db.session.query(
        db.func.count(Audit.id).label('total'),
        db.func.sum(db.case((Audit.status == 'open', 1), else_=0)).label('open'),
        db.func.sum(db.case((Audit.status == 'closed', 1), else_=0)).label('closed')
    ).filter(
        Audit.audit_date >= current_month_start,
        Audit.audit_date < current_month_end
    ).first()

    monthly_one_month = {
        'month': current_month_start.strftime('%B %Y'),
        'total': current_month_results.total or 0,
        'open': current_month_results.open or 0,
        'closed': current_month_results.closed or 0
    }

    monthly_results = db.session.query(
        db.func.strftime('%Y-%m', Audit.audit_date).label('month'),
        db.func.count(Audit.id).label('total'),
        db.func.sum(db.case((Audit.status == 'open', 1), else_=0)).label('open'),
        db.func.sum(db.case((Audit.status == 'closed', 1), else_=0)).label('closed')
    ).filter(
        Audit.audit_date >= date(2025, 5, 1)
    ).group_by('month').order_by('month').all()

    monthly_map = {}
    for r in monthly_results:
        monthly_map[r.month] = {
            'total': r.total or 0,
            'open': r.open or 0,
            'closed': r.closed or 0
        }

    start_month = date(2025, 5, 1)
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
        'monthly_one_month': monthly_one_month,
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
    return render_template('audits.html', audits=all_audits)


@app.route('/audits/add', methods=['GET', 'POST'])
@login_required
def add_audit():
    if request.method == 'POST':
        audit_date = parse_date(request.form.get('audit_date', ''))
        ygct_plant1 = request.form.get('ygct_plant1', '').strip()
        ygct_plant2 = request.form.get('ygct_plant2', '').strip()
        ygct_plant3 = request.form.get('ygct_plant3', '').strip()
        zonal_leader = request.form.get('zonal_leader', '').strip()
        nc_category = request.form.get('nc_category', '').strip()
        description = request.form.get('description', '').strip()
        action_taken_details = request.form.get('action_taken_details', '').strip()
        responsible_hod = request.form.get('responsible_hod', '').strip()
        responsible_email = request.form.get('responsible_email', '').strip()
        target_date = parse_date(request.form.get('target_date', ''))
        status = request.form.get('status', 'open')

        before_file = request.files.get('before_image')
        after_file = request.files.get('after_image')
        before_image = save_upload(before_file)
        after_image = save_upload(after_file)

        errors = []
        if not audit_date:
            errors.append('Audit Date is required.')
        if not ygct_plant1 and not ygct_plant2 and not ygct_plant3:
            errors.append('At least one plant (Plant1, Plant2, or Plant3) is required.')
        if not zonal_leader:
            errors.append('Zonal Leader is required.')
        if not nc_category:
            errors.append('NC Category is required.')
        if not description:
            errors.append('Description of Non Conformity is required.')
        if not responsible_hod:
            errors.append('Responsible HOD is required.')
        if not responsible_email:
            errors.append('Responsible Email is required.')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('audit_form.html', form=request.form)

        audit = Audit(
            audit_date=audit_date,
            ygct_plant1=ygct_plant1,
            ygct_plant2=ygct_plant2,
            ygct_plant3=ygct_plant3,
            zonal_leader=zonal_leader,
            nc_category=nc_category,
            description=description,
            before_image=before_image,
            after_image=after_image,
            action_taken_details=action_taken_details,
            responsible_hod=responsible_hod,
            responsible_email=responsible_email,
            target_date=target_date,
            status=status,
        )
        db.session.add(audit)
        db.session.commit()

        create_audit_alert(audit)

        flash('Audit record created successfully! Alert sent to responsible person.', 'success')
        return redirect(url_for('audits'))

    return render_template('audit_form.html')


@app.route('/audits/edit/<int:audit_id>', methods=['GET', 'POST'])
@login_required
def edit_audit(audit_id):
    audit = db.session.get(Audit, audit_id)
    if not audit:
        flash('Audit record not found.', 'error')
        return redirect(url_for('audits'))

    if request.method == 'POST':
        audit.audit_date = parse_date(request.form.get('audit_date', '')) or audit.audit_date
        audit.ygct_plant1 = request.form.get('ygct_plant1', '').strip()
        audit.ygct_plant2 = request.form.get('ygct_plant2', '').strip()
        audit.ygct_plant3 = request.form.get('ygct_plant3', '').strip()
        audit.zonal_leader = request.form.get('zonal_leader', '').strip()
        audit.nc_category = request.form.get('nc_category', '').strip()
        audit.description = request.form.get('description', '').strip()
        audit.action_taken_details = request.form.get('action_taken_details', '').strip()
        audit.responsible_hod = request.form.get('responsible_hod', '').strip()
        audit.responsible_email = request.form.get('responsible_email', '').strip()
        audit.target_date = parse_date(request.form.get('target_date', ''))
        audit.status = request.form.get('status', 'open')
        audit.updated_at = datetime.utcnow()

        before_file = request.files.get('before_image')
        after_file = request.files.get('after_image')
        if before_file and before_file.filename:
            audit.before_image = save_upload(before_file) or audit.before_image
        if after_file and after_file.filename:
            audit.after_image = save_upload(after_file) or audit.after_image

        errors = []
        if not audit.ygct_plant1 and not audit.ygct_plant2 and not audit.ygct_plant3:
            errors.append('At least one plant (Plant1, Plant2, or Plant3) is required.')
        if not audit.zonal_leader:
            errors.append('Zonal Leader is required.')
        if not audit.nc_category:
            errors.append('NC Category is required.')
        if not audit.description:
            errors.append('Description of Non Conformity is required.')
        if not audit.responsible_hod:
            errors.append('Responsible HOD is required.')
        if not audit.responsible_email:
            errors.append('Responsible Email is required.')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('audit_form.html', audit=audit, form=request.form)

        db.session.commit()
        flash('Audit record updated successfully!', 'success')
        return redirect(url_for('audits'))

    return render_template('audit_form.html', audit=audit)


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
        db.func.sum(db.case((Audit.status == 'closed', 1), else_=0)).label('closed_count'),
        db.func.max(Audit.audit_date).label('latest_date')
    ).group_by(Audit.responsible_hod).order_by(Audit.responsible_hod).all()
    return render_template('hod_summary.html', hod_data=hod_data)


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
    subject = f"New Audit Alert: {audit.nc_category} - {audit.ygct_plant1}"
    plant_info = f"Plant1: {audit.ygct_plant1}\nPlant2: {audit.ygct_plant2}\nPlant3: {audit.ygct_plant3}"
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
        f"<p><strong>Plant1:</strong> {audit.ygct_plant1}</p>"
        f"<p><strong>Plant2:</strong> {audit.ygct_plant2}</p>"
        f"<p><strong>Plant3:</strong> {audit.ygct_plant3}</p>"
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
    test_email = request.args.get('email', '')
    if not test_email:
        return 'Usage: /test-email?email=you@example.com', 400
    
    smtp_host = os.getenv('SMTP_HOST', '').strip()
    smtp_user = os.getenv('SMTP_USERNAME', '').strip()
    smtp_pass = os.getenv('SMTP_PASSWORD', '').strip()
    
    if not smtp_host or not smtp_user or not smtp_pass:
        return f"SMTP not configured. Set SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD in .env file. Current: host={smtp_host or 'MISSING'}, user={smtp_user or 'MISSING'}, pass={'SET' if smtp_pass else 'MISSING'}", 500
    
    sent, error_msg = send_email(
        test_email,
        'Test Email from YG1 Monitor',
        'This is a test email. If you receive this, SMTP is configured correctly.',
        '<h3>Test Email</h3><p>This is a test email from YG1 Monitor.</p>'
    )
    if sent:
        return f"Email sent to {test_email}", 200
    return f"Email failed: {error_msg}", 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@company.com', role='admin')
            admin.set_password('Admin@123')
            db.session.add(admin)
            db.session.commit()
            print('[OK] Default admin created: username="admin" password="Admin@123"')

    app.run(debug=True)
