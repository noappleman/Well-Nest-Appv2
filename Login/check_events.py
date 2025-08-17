from app import app, db, Event

with app.app_context():
    events = Event.query.all()
    print(f'Total events: {len(events)}')
    for e in events:
        print(f'Event {e.id}: {e.title} by user {e.user_id}')
