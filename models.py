from extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='coordinator')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Rule(db.Model):
    rule_name = db.Column(db.String(120), nullable=False)
    item = db.Column(db.String(100), nullable=False)
    required_location = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Rule {self.rule_name}>'


class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    audit_date = db.Column(db.Date, nullable=False)
    ygct_plant1 = db.Column(db.String(100), nullable=False)
    zonal_leader = db.Column(db.String(100), nullable=False)
    nc_category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    before_image = db.Column(db.String(200))
    after_image = db.Column(db.String(200))
    action_taken_details = db.Column(db.Text)
    responsible_hod = db.Column(db.String(100), nullable=False)
    responsible_email = db.Column(db.String(120), nullable=False)
    target_date = db.Column(db.Date)
    status = db.Column(db.String(20), nullable=False, default='open')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    alerts = db.relationship('Alert', backref='audit', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Audit {self.id} - {self.nc_category}>'


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey('audit.id'), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    responsible_email = db.Column(db.String(120), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Alert {self.id} - {self.subject}>'
