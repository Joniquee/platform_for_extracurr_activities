# -*- coding: utf-8 -*-
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Инициализация db здесь, чтобы избежать циклических импортов
db = SQLAlchemy()

# Association table for many-to-many relationship between users and organizations
organization_members = db.Table('organization_members',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('organization_id', db.Integer, db.ForeignKey('organizations.id'), primary_key=True)
)

# Minimal addition for event registrations
event_registrations = db.Table('event_registrations',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('event_id', db.Integer, db.ForeignKey('events.id'), primary_key=True),
    db.Column('registered_at', db.DateTime, default=datetime.utcnow)
)

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Organization(db.Model):
    __tablename__ = 'organizations'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    leader_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    leader = db.relationship('User', backref='led_organizations')
    events = db.relationship('Event', backref='organization', lazy=True)
    vacancies = db.relationship('Vacancy', backref='organization', lazy=True)
    members = db.relationship('User', secondary=organization_members, 
                             backref=db.backref('organizations', lazy=True))
    
    def __repr__(self):
        return f'<Organization {self.name}>'

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.Text)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'))
    
    # Minimal addition - relationship for registrations
    registrations = db.relationship('User', secondary=event_registrations,
                                  backref=db.backref('registered_events', lazy='dynamic'))
    
    def __repr__(self):
        return f'<Event {self.title} on {self.date}>'

class Vacancy(db.Model):
    __tablename__ = 'vacancies'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<Vacancy {self.title}>'

class Application(db.Model):
    __tablename__ = 'applications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    vacancy_id = db.Column(db.Integer, db.ForeignKey('vacancies.id'))
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    telegram = db.Column(db.String(50))
    course = db.Column(db.Integer, nullable=False)
    study_group = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='pending')
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='applications')
    vacancy = db.relationship('Vacancy', backref='applications')
    
    def __repr__(self):
        return f'<Application #{self.id} for {self.vacancy.title}>'