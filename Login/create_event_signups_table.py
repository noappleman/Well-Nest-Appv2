from app import app, db, EventSignup

with app.app_context():
    db.create_all()
    print("EventSignup table created successfully!")
