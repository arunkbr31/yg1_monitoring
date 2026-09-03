"""Seed the database with a default admin user and sample rules."""
from app import app, db
from models import User, Rule


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

    if Rule.query.count() == 0:
        sample_rules = [
            Rule(rule_name='Fire Extinguisher Placement', item='Fire Extinguisher',
                 required_location='Near Boiler Area - Bay 3',
                 description='Fire extinguishers must be accessible near boiler areas'),
            Rule(rule_name='First Aid Kit Location', item='First Aid Kit',
                 required_location='Main Office Wall',
                 description='First aid kit must be on the main office wall'),
            Rule(rule_name='Safety Helmet Storage', item='Safety Helmet',
                 required_location='Tool Crib - Shelf A',
                 description='Safety helmets must be stored on Shelf A of the tool crib'),
        ]
        for r in sample_rules:
            db.session.add(r)
        db.session.commit()
        print(f'[OK] Seeded {len(sample_rules)} sample rules.')
    else:
        print('[INFO] Rules already exist. Skipping.')

    print('Database tables ready.')
