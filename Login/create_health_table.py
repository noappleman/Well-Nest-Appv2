from app import app, db
from app import HealthMetric

# Create the application context
with app.app_context():
    # Create the health_metrics table
    db.create_all()
    print("Health metrics table created successfully!")
