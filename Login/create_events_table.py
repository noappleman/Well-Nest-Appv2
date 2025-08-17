from app import app, db, Event

with app.app_context():
    db.create_all()
    print("Events table created successfully!")
