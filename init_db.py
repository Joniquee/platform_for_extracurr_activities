# init_db.py
from app import app, db
from models import User, Organization, Event, Vacancy
from datetime import datetime
from werkzeug.security import generate_password_hash

# -*- coding: utf-8 -*-
def initialize_database():
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Add initial admin user if none exists
        if not User.query.first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password=generate_password_hash('securepassword123'),  # Always hash passwords
                role='admin'
            )
            db.session.add(admin)
            
            # Add sample data (optional)
            org = Organization(
                name='Sample Organization',
                description='Example organization for demonstration'
            )
            db.session.add(org)
            
            event = Event(
                title='Welcome Event',
                date=datetime.utcnow(),
                description='Initial system event'
            )
            db.session.add(event)
            
            db.session.commit()
            print("Database initialized successfully")
        else:
            print("Database already contains data - no initialization needed")

if __name__ == '__main__':
    initialize_database()