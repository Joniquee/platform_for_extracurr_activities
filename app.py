# -*- coding: utf-8 -*-
from flask import Flask, request, render_template, redirect, url_for, flash
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    current_user,
    login_required
)
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from models import db, User, Organization, Event, Vacancy


def create_app():
    app = Flask(__name__, template_folder='templates')
    app.config.from_object(Config)

    db.init_app(app)

    login_manager = LoginManager(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    register_routes(app)

    with app.app_context():
        db.create_all()

        # Создаём root admin если его нет
        if not User.query.filter_by(role='root_admin').first():
            root_admin = User(
                username='root_admin',
                email='root@example.com',
                password=generate_password_hash('secure_root_password'),
                role='root_admin'
            )
            db.session.add(root_admin)
            db.session.commit()
            print("Root admin created: root@example.com / secure_root_password")

    return app


def register_routes(app):
    """Регистрация всех маршрутов"""

    # Открытые маршруты (без авторизации)
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/organizations')
    def organizations():
        orgs = Organization.query.all()
        return render_template('organizations.html', organizations=orgs)

    @app.route('/events')
    def events():
        events_list = Event.query.order_by(Event.date).all()
        return render_template('events.html', events=events_list)

    @app.route('/vacancies')
    def vacancies():
        vacancies_list = Vacancy.query.order_by(Vacancy.created_at.desc()).all()
        return render_template('vacancies.html', vacancies=vacancies_list)

    # Авторизация/регистрация
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')

            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'error')
                return redirect(url_for('register'))

            new_user = User(
                username=username,
                email=email,
                password=generate_password_hash(password, method='pbkdf2:sha256'),
                role='user'
            )

            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()

            if user and check_password_hash(user.password, password):
                login_user(user, remember=True)  # Добавлен remember=True
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Invalid email or password', 'error')

        return render_template('login.html')

    @app.route('/logout')
    def logout():
        logout_user()
        return redirect(url_for('index'))

    # Защищённые маршруты (требуют авторизации)
    @app.route('/dashboard')
    @login_required
    def dashboard():
        events = Event.query.order_by(Event.date).limit(5).all()
        return render_template('dashboard.html', events=events)

    @app.route('/profile')
    @login_required
    def profile():
        return render_template('profile.html', user=current_user)

    @app.route('/update_profile', methods=['POST'])
    @login_required
    def update_profile():
        # Получаем данные из формы
        username = request.form.get('username')
        email = request.form.get('email')

        # Проверяем уникальность email
        if email != current_user.email:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email already registered by another user', 'error')
                return redirect(url_for('profile'))

        # Обновляем данные пользователя
        current_user.username = username
        current_user.email = email
        db.session.commit()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    @app.route('/change_password', methods=['POST'])
    @login_required
    def change_password():
        # Получаем данные из формы
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Проверяем текущий пароль
        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('profile'))

        # Проверяем совпадение новых паролей
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('profile'))

        # Обновляем пароль
        current_user.password = generate_password_hash(new_password)
        db.session.commit()

        flash('Password changed successfully!', 'success')
        return redirect(url_for('profile'))

    # +++ НОВЫЕ МАРШРУТЫ ДЛЯ УПРАВЛЕНИЯ АДМИНИСТРАТОРАМИ +++
    # +++ НОВЫЕ МАРШРУТЫ ДЛЯ УПРАВЛЕНИЯ АДМИНИСТРАТОРАМИ +++
    @app.route('/admin/users')
    @login_required
    def admin_users():
        # Разрешаем доступ только root_admin и admin
        if current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))

        users = User.query.order_by(User.id).all()
        return render_template('admin/users.html', users=users)

    @app.route('/admin/create_admin', methods=['GET', 'POST'])
    @login_required
    def create_admin():
        # Разрешаем доступ только root_admin и admin
        if current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')

            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'error')
                return redirect(url_for('create_admin'))

            new_admin = User(
                username=username,
                email=email,
                password=generate_password_hash(password, method='pbkdf2:sha256'),
                role='admin'  # Все новые админы создаются как обычные админы
            )

            db.session.add(new_admin)
            db.session.commit()

            flash('New admin created successfully!', 'success')
            return redirect(url_for('admin_users'))

        return render_template('admin/create_admin.html')

    @app.route('/admin/promote_to_admin/<int:user_id>')
    @login_required
    def promote_to_admin(user_id):
        # Проверяем права доступа
        if current_user.role not in ['admin', 'root_admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))

        user = User.query.get_or_404(user_id)
        if user.role == 'root_admin':
            flash('Cannot modify root admin', 'error')
        elif user.role == 'admin':
            flash('User is already an admin', 'warning')
        else:
            user.role = 'admin'
            db.session.commit()
            flash(f'User {user.username} promoted to admin', 'success')

        return redirect(url_for('admin_users'))

    @app.route('/admin/demote_admin/<int:user_id>')
    @login_required
    def demote_admin(user_id):
        # Проверяем права доступа
        if current_user.role != 'root_admin':  # Только root_admin может понижать админов
            flash('Access denied. Only root admin can demote administrators.', 'error')
            return redirect(url_for('dashboard'))

        user = User.query.get_or_404(user_id)

        if user.role == 'root_admin':
            flash('Cannot demote root admin', 'error')
        elif user.role == 'user':
            flash('User is not an admin', 'warning')
        else:
            user.role = 'user'
            db.session.commit()
            flash(f'User {user.username} demoted to regular user', 'success')

        return redirect(url_for('admin_users'))


app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')