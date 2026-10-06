from app import app, db

with app.app_context():
    db.create_all()
    from models import User
    if not User.query.first():
        admin = User(username='admin', email='admin@company.com', role='admin')
        admin.set_password('Admin@123')
        db.session.add(admin)
        db.session.commit()

    with app.test_client() as c:
        c.post('/login', data={'id': 'arun123', 'password': '2av12me003'})
        resp = c.get('/audits/export/pdf')
        with open('test_output.pdf', 'wb') as f:
            f.write(resp.data)
        print('PDF saved: %d bytes' % len(resp.data))
        # Check it starts with PDF header
        print('Starts with %%PDF:', resp.data[:4])
print('Done!')
