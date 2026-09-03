from extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


class User(UserMixin, db.Model):
    """Admin / Coordinator user with secure password hashing."""
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
    """Company rule defining where an item must be placed."""
    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(120), nullable=False)
    item = db.Column(db.String(100), nullable=False)
    required_location = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    placements = db.relationship('Placement', backref='rule', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Rule {self.rule_name}>'


class Placement(db.Model):
    """Record of an item's actual location, checked against a rule."""
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=False)
    zone = db.Column(db.String(100), nullable=False)
    current_location = db.Column(db.String(200), nullable=False)
    responsible_person = db.Column(db.String(100), nullable=False)
    coordinator_email = db.Column(db.String(120), nullable=False)
    violation_reason = db.Column(db.Text)
    status = db.Column(db.String(20), default='open')
    is_compliant = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    alerts = db.relationship('Alert', backref='placement', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Placement {self.id} - {self.rule.item} - {self.status}>'


class Alert(db.Model):
    """Alert sent to a coordinator when a placement violates a rule."""
    id = db.Column(db.Integer, primary_key=True)
    placement_id = db.Column(db.Integer, db.ForeignKey('placement.id'), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    coordinator_email = db.Column(db.String(120), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Alert {self.id} - {self.subject}>'
