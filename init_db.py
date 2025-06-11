# -*- coding: utf-8 -*-
from app import create_app
from models import db, User, Organization, Event, Vacancy
from datetime import datetime
from werkzeug.security import generate_password_hash

def initialize_database():
    app = create_app()
    with app.app_context():
        db.create_all()
        
        if not User.query.first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password=generate_password_hash('securepassword123'),
                role='admin'
            )
            db.session.add(admin)
            
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