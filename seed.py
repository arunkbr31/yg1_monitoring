"""Seed the database with a default admin user."""
from app import app, db
from models import User


with app.app_context():
    db.create_all()

    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@company.com', role='admin')
        admin.set_password('Admin@123')
        db.session.add(admin)
        db.session.commit()
        print('[OK] Default admin created: username="admin" password="Admin@123"')
    else:
        print('[INFO] Admin user already exists. Skipping.')

    print('Database tables ready.')
