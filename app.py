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
from models import User, Rule, Placement, Alert


# ── Load environment variables (secret keys, etc.) ──
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_upload(file_storage):
    """Save an uploaded before/after image and return its stored filename, or None."""
    if not file_storage or file_storage.filename == '':
        return None
    if not allowed_file(file_storage.filename):
        return None
    ext = file_storage.filename.rsplit('.', 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{ext}"
    file_storage.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return filename


def parse_date(value):
    """Parse an HTML date input (YYYY-MM-DD) into a date object, or None."""
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        return None


db.init_app(app)

# ── Flask-Login setup ──
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ── Email helpers ──
def send_email(to_email, subject, body_text, body_html=None):
    """Send an email via SMTP if credentials are configured, otherwise log to console."""
    smtp_host = os.getenv('SMTP_HOST', '').strip()
    smtp_port = int(os.getenv('SMTP_PORT', '587') or '587')
    smtp_user = os.getenv('SMTP_USERNAME', '').strip()
    smtp_pass = os.getenv('SMTP_PASSWORD', '').strip()
    from_email = os.getenv('ALERT_FROM_EMAIL', '').strip() or smtp_user

    if not smtp_host or not smtp_user or not smtp_pass:
        # Log to console instead of sending
        print(f"[EMAIL LOGGED] To: {to_email} | Subject: {subject}")
        print(f"  Body: {body_text}")
        return False

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
        return True
    except Exception as e:
        print(f"[EMAIL FAILED] {e}")
        return False


# ── Helpers ──
def get_status_counts():
    """Return counts for dashboard cards: total, compliant, violations, open, closed."""
    total = Placement.query.count()
    compliant = Placement.query.filter_by(is_compliant=True).count()
    violations = Placement.query.filter_by(is_compliant=False).count()
    open_count = Placement.query.filter_by(status='open').count()
    closed_count = Placement.query.filter_by(status='closed').count()
    return {
        'total': total,
        'compliant': compliant,
        'violations': violations,
        'open': open_count,
        'closed': closed_count,
    }


def check_placement_compliance(placement):
    """Set is_compliant based on whether current_location matches required_location."""
    is_compliant = (
        placement.current_location.strip().lower() ==
        placement.rule.required_location.strip().lower()
    )
    placement.is_compliant = is_compliant
    return is_compliant


def create_violation_alert(placement):
    """Create and send an alert for a non-compliant placement."""
    subject = f"Violation Alert: {placement.rule.item} in {placement.zone}"
    body_text = (
        f"A placement violation has been detected.\n\n"
        f"Item: {placement.rule.item}\n"
        f"Rule: {placement.rule.rule_name}\n"
        f"Required Location: {placement.rule.required_location}\n"
        f"Current Location: {placement.current_location}\n"
        f"Zone: {placement.zone}\n"
        f"Responsible: {placement.responsible_person}\n"
        f"Violation Reason: {placement.violation_reason or 'N/A'}\n\n"
        f"Please take corrective action."
    )
    body_html = (
        f"<h3>Violation Alert: {placement.rule.item}</h3>"
        f"<p><strong>Rule:</strong> {placement.rule.rule_name}</p>"
        f"<p><strong>Required Location:</strong> {placement.rule.required_location}</p>"
        f"<p><strong>Current Location:</strong> {placement.current_location}</p>"
        f"<p><strong>Zone:</strong> {placement.zone}</p>"
        f"<p><strong>Responsible:</strong> {placement.responsible_person}</p>"
        f"<p><strong>Violation Reason:</strong> {placement.violation_reason or 'N/A'}</p>"
        f"<p>Please take corrective action.</p>"
    )

    alert = Alert(
        placement_id=placement.id,
        subject=subject,
        message=body_text,
        coordinator_email=placement.coordinator_email,
        sent_at=datetime.utcnow(),
    )
    db.session.add(alert)
    db.session.commit()

    sent = send_email(placement.coordinator_email, subject, body_text, body_html)
    if sent:
        flash(f"Alert sent to {placement.coordinator_email}.", 'success')
    else:
        flash(f"Placement violation detected. Alert logged for {placement.coordinator_email}.", 'warning')

    return alert


# ── Error handlers ──
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


# ── Authentication Routes ──
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


# ── Dashboard ──
@app.route('/')
@login_required
def dashboard():
    placements = Placement.query.order_by(Placement.created_at.desc()).limit(10).all()
    alerts = Alert.query.order_by(Alert.sent_at.desc()).limit(10).all()
    counts = get_status_counts()

    return render_template(
        'dashboard.html',
        placements=placements,
        alerts=alerts,
        counts=counts,
        now=datetime.utcnow()
    )


# ── Charts API (for Chart.js) ──
@app.route('/api/charts')
@login_required
def charts_data():
    """JSON endpoint for dashboard charts."""
    counts = get_status_counts()

    # Breakdown per Rule: violations vs compliant
    rule_stats = []
    for rule in Rule.query.all():
        total = len(rule.placements)
        if total == 0:
            continue
        compliant_count = sum(1 for p in rule.placements if p.is_compliant)
        violations_count = sum(1 for p in rule.placements if not p.is_compliant)
        rule_stats.append({
            'rule': rule.rule_name or rule.item,
            'total': total,
            'violations': violations_count,
            'compliant': compliant_count,
        })

    # Weekly trend (last 7 days) based on placement created_at
    today = date.today()
    weekly = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_open = Placement.query.filter(
            Placement.status == 'open',
            db.func.date(Placement.created_at) == day
        ).count()
        day_closed = Placement.query.filter(
            Placement.status == 'closed',
            db.func.date(Placement.created_at) == day
        ).count()
        weekly.append({
            'date': day.strftime('%d %b'),
            'open': day_open,
            'closed': day_closed,
        })

    return jsonify({
        'counts': counts,
        'rule_stats': rule_stats,
        'weekly': weekly,
    })


# ── Rules ──
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
        flash('Rule and all its placements deleted.', 'info')
    return redirect(url_for('rules'))


# ── Placements ──
@app.route('/placements')
@login_required
def placements():
    all_placements = Placement.query.order_by(Placement.created_at.desc()).all()
    return render_template('placements.html', placements=all_placements)


@app.route('/placements/add', methods=['GET', 'POST'])
@login_required
def add_placement():
    if request.method == 'POST':
        rule_id = request.form.get('rule_id', '')
        zone = request.form.get('zone', '').strip()
        current_location = request.form.get('current_location', '').strip()
        responsible_person = request.form.get('responsible_person', '').strip()
        coordinator_email = request.form.get('coordinator_email', '').strip()
        violation_reason = request.form.get('violation_reason', '').strip()

        errors = []
        if not rule_id:
            errors.append('Rule is required.')
        if not zone:
            errors.append('Zone is required.')
        if not current_location:
            errors.append('Current Location is required.')
        if not responsible_person:
            errors.append('Responsible Person is required.')
        if not coordinator_email:
            errors.append('Coordinator Email is required.')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('placement_form.html', rules=Rule.query.all(), form=request.form)

        rule = db.session.get(Rule, int(rule_id))
        if not rule:
            flash('Selected rule not found.', 'error')
            return render_template('placement_form.html', rules=Rule.query.all(), form=request.form)

        placement = Placement(
            rule_id=rule.id,
            zone=zone,
            current_location=current_location,
            responsible_person=responsible_person,
            coordinator_email=coordinator_email,
            violation_reason=violation_reason,
            status='open',
        )
        db.session.add(placement)
        db.session.flush()

        check_placement_compliance(placement)

        if not placement.is_compliant:
            create_violation_alert(placement)
        else:
            db.session.commit()
            flash('Placement recorded. Item is compliant. ✓', 'success')

        return redirect(url_for('placements'))

    all_rules = Rule.query.all()
    return render_template('placement_form.html', rules=all_rules)


@app.route('/placements/close/<int:placement_id>', methods=['POST'])
@login_required
def close_placement(placement_id):
    placement = db.session.get(Placement, placement_id)
    if placement:
        placement.status = 'closed'
        placement.updated_at = datetime.utcnow()
        db.session.commit()
        flash('Placement marked as closed.', 'success')
    else:
        flash('Placement not found.', 'error')
    return redirect(url_for('placements'))


@app.route('/placements/reopen/<int:placement_id>', methods=['POST'])
@login_required
def reopen_placement(placement_id):
    placement = db.session.get(Placement, placement_id)
    if placement:
        placement.status = 'open'
        placement.updated_at = datetime.utcnow()
        db.session.commit()
        flash('Placement reopened.', 'info')
    else:
        flash('Placement not found.', 'error')
    return redirect(url_for('placements'))


@app.route('/placements/delete/<int:placement_id>', methods=['POST'])
@login_required
def delete_placement(placement_id):
    placement = db.session.get(Placement, placement_id)
    if placement:
        db.session.delete(placement)
        db.session.commit()
        flash('Placement record deleted.', 'info')
    else:
        flash('Placement not found.', 'error')
    return redirect(url_for('placements'))


# ── Alerts ──
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


# ── User Management (Admin only) ──
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
