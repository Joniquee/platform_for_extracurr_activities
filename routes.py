# -*- coding: utf-8 -*-
from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from models import User, Organization, Event

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Homepage route"""
    return render_template('index.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """
    User dashboard route
    Requires authentication
    """
    # Get user's upcoming events (example of enhanced functionality)
    upcoming_events = Event.query.filter(
        Event.date >= datetime.utcnow()
    ).order_by(Event.date.asc()).limit(5).all()
    
    return render_template('dashboard.html', 
                         user=current_user,
                         events=upcoming_events)

@main_bp.route('/profile')
@login_required
def profile():
    """User profile route"""
    return render_template('profile.html', user=current_user)

@main_bp.route('/admin')
@login_required
def admin_panel():
    """Admin dashboard route"""
    if current_user.role != 'admin':
        return redirect(url_for('main.dashboard'))
    
    users = User.query.order_by(User.username).all()
    return render_template('admin_panel.html', users=users)