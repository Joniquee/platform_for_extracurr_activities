# -*- coding: utf-8 -*-
from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    current_user,
    login_required
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from config import Config
from models import db, User, Organization, Event, Vacancy, Application, VerificationCode
from flask import jsonify
from flask_mail import Mail, Message

mail = Mail()
def create_app():
    app = Flask(__name__, template_folder='templates')
    app.config.from_object(Config)

    import logging
    logging.basicConfig(level=logging.DEBUG)
    db.init_app(app)
    mail.init_app(app)

    login_manager = LoginManager(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    register_routes(app)

    with app.app_context():
        db.create_all()

        # Create root admin if doesn't exist
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
    """Register all routes"""

    @app.route('/send_verification', methods=['POST'])
    def _send_verification_email(email):
        try:
            # Удаляем старые коды для этого email
            VerificationCode.query.filter_by(email=email).delete()

            # Создаем и сохраняем новый код
            verification = VerificationCode(email=email)
            db.session.add(verification)
            db.session.commit()

            # Отправляем письмо
            msg = Message(
                'Ваш код подтверждения',
                recipients=[email],
                body=f'Ваш код подтверждения: {verification.code}'
            )
            mail.send(msg)
            return True
        except Exception as e:
            print(f"Failed to send email: {e}")
            db.session.rollback()
            return False

    @app.route('/send_verification', methods=['POST'])
    def send_verification():
        """Отправка кода подтверждения на email"""
        email = request.form.get('email')
        if not email:
            return jsonify({'status': 'error', 'message': 'Email не указан'}), 400

        try:
            # Удаляем старые коды для этого email
            VerificationCode.query.filter_by(email=email).delete()

            # Создаем и сохраняем новый код
            verification = VerificationCode(email=email)
            db.session.add(verification)
            db.session.commit()

            # Отправляем письмо
            msg = Message(
                'Ваш код подтверждения',
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[email],
                body=f'Ваш код подтверждения: {verification.code}'
            )
            mail.send(msg)
            return jsonify({'status': 'success'})
        except Exception as e:
            app.logger.error(f"Ошибка отправки письма: {e}")
            db.session.rollback()
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/verify_email', methods=['GET', 'POST'])
    def verify_email():
        if request.method == 'POST':
            email = request.form.get('email')
            user_code = request.form.get('verification_code')

            verification = VerificationCode.query.filter_by(email=email).first()

            if not verification or verification.code != user_code:
                flash('Неверный код подтверждения', 'error')
                return redirect(url_for('verify_email'))

            if not verification.is_valid():
                flash('Срок действия кода истек', 'error')
                return redirect(url_for('verify_email'))

            # Помечаем код как использованный
            verification.is_used = True
            db.session.commit()

            # Находим или создаем пользователя
            user = User.query.filter_by(email=email).first()
            if not user:
                # Создаем нового пользователя из временных данных в сессии
                temp_user = session.get('temp_user')
                if not temp_user:
                    flash('Сессия истекла. Зарегистрируйтесь снова.', 'error')
                    return redirect(url_for('register'))

                user = User(
                    username=temp_user['username'],
                    email=email,
                    password=temp_user['password']
                )
                db.session.add(user)
                db.session.commit()

            # Выполняем вход пользователя
            login_user(user)
            flash('Email успешно подтвержден!', 'success')
            return redirect(url_for('dashboard'))  # Перенаправляем в личный кабинет

        return render_template('verify_email.html', email=request.args.get('email'))
    @app.route('/resend_code')
    def resend_code():
        email = request.args.get('email')
        _send_verification_email(email)
        flash('Новый код отправлен на ваш email', 'info')
        return redirect(url_for('verify_email', email=email))

    # Обновите маршрут регистрации
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')

            if User.query.filter_by(email=email).first():
                flash('Email уже зарегистрирован', 'error')
                return redirect(url_for('register'))

            # Сохраняем данные в сессии перед подтверждением email
            session['temp_user'] = {
                'username': username,
                'email': email,
                'password': generate_password_hash(password)
            }

            # Отправляем код подтверждения
            _send_verification_email(email)
            return redirect(url_for('verify_email', email=email))

        return render_template('register.html')

    # Обновите маршрут входа
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()

            if user and check_password_hash(user.password, password):
                # Сохраняем ID пользователя в сессии для верификации
                session['login_user_id'] = user.id
                _send_verification_email(email)
                return redirect(url_for('verify_email', email=email))
            else:
                flash('Неверный email или пароль', 'error')

        return render_template('login.html')

    @app.route('/logout')
    def logout():
        logout_user()
        return redirect(url_for('index'))

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

    #vacancies logic
    @app.route('/vacancy/<int:vacancy_id>')
    def vacancy_details(vacancy_id):
        vacancy = Vacancy.query.get_or_404(vacancy_id)
        organization = Organization.query.get(vacancy.organization_id) if vacancy.organization_id else None
        return render_template('vacancy_details.html', 
                             vacancy=vacancy,
                             organization=organization)
    @app.route('/vacancy/<int:vacancy_id>/edit', methods=['GET', 'POST'])
    @login_required
    def edit_vacancy(vacancy_id):
        vacancy = Vacancy.query.get_or_404(vacancy_id)
        organization = Organization.query.get(vacancy.organization_id) if vacancy.organization_id else None
    
        # Проверка прав
        if current_user.role not in ['admin', 'root_admin']:
            if not organization or current_user.id != organization.leader_id:
                flash('Access denied', 'error')
                return redirect(url_for('vacancy_details', vacancy_id=vacancy.id))

        if request.method == 'POST':
            vacancy.title = request.form.get('title')
            vacancy.description = request.form.get('description')
            vacancy.requirements = request.form.get('requirements')
            db.session.commit()
            flash('Vacancy updated successfully!', 'success')
            return redirect(url_for('vacancy_details', vacancy_id=vacancy.id))
    
        organizations = Organization.query.all()
        return render_template('edit_vacancy.html', 
                             vacancy=vacancy,
                             organizations=organizations)

    @app.route('/vacancy/<int:vacancy_id>/delete', methods=['POST'])
    @login_required
    def delete_vacancy(vacancy_id):
        vacancy = Vacancy.query.get_or_404(vacancy_id)
        organization = Organization.query.get(vacancy.organization_id) if vacancy.organization_id else None
    
        # Проверка прав
        if current_user.role not in ['admin', 'root_admin']:
            if not organization or current_user.id != organization.leader_id:
                flash('Access denied', 'error')
                return redirect(url_for('vacancy_details', vacancy_id=vacancy.id))

        db.session.delete(vacancy)
        db.session.commit()
        flash('Vacancy has been deleted', 'success')
        return redirect(url_for('vacancies'))

    @app.route('/vacancy/<int:vacancy_id>/apply', methods=['GET', 'POST'])
    @login_required
    def apply_for_vacancy(vacancy_id):
        vacancy = Vacancy.query.get_or_404(vacancy_id)
    
        # Проверяем, не подавал ли пользователь уже заявку
        existing_application = Application.query.filter_by(
            user_id=current_user.id,
            vacancy_id=vacancy.id
        ).first()
    
        if existing_application:
            flash('You have already applied for this vacancy', 'warning')
            return redirect(url_for('vacancy_details', vacancy_id=vacancy.id))
    
        if request.method == 'POST':
            # Создаем новую заявку
            application = Application(
                user_id=current_user.id,
                vacancy_id=vacancy.id,
                full_name=request.form['full_name'],
                email=request.form['email'],
                phone=request.form['phone'],
                telegram=request.form['telegram'],
                course=request.form['course'],
                study_group=request.form['study_group'],
                status='pending'
            )
        
            db.session.add(application)
            db.session.commit()
        
            flash('Your application has been submitted successfully!', 'success')
            return redirect(url_for('vacancy_details', vacancy_id=vacancy.id))
    
        return render_template('apply_for_vacancy.html', vacancy=vacancy)


    @app.route('/organization/<int:org_id>/applications')
    @login_required
    def organization_applications(org_id):
        org = Organization.query.get_or_404(org_id)
    
        # Проверка прав (только лидер организации или админы)
        if org.leader_id != current_user.id and current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
    
        # Получаем все заявки для вакансий этой организации
        applications = db.session.query(Application).join(Vacancy).filter(
            Vacancy.organization_id == org_id
        ).order_by(Application.status, Application.applied_at.desc()).all()
    
        return render_template('organization_applications.html', 
                             organization=org,
                             applications=applications)

    @app.route('/application/<int:app_id>/update_status', methods=['POST'])
    @login_required
    def update_application_status(app_id):
        application = Application.query.get_or_404(app_id)
        vacancy = application.vacancy
        org = vacancy.organization
    
        # Проверка прав (только лидер организации или админы)
        if org.leader_id != current_user.id and current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
    
        new_status = request.form.get('status')
        if new_status not in ['accepted', 'rejected', 'pending']:
            flash('Invalid status', 'error')
            return redirect(url_for('organization_applications', org_id=org.id))
    
        application.status = new_status
        db.session.commit()
    
        # Если заявка принята, добавляем пользователя в члены организации
        if new_status == 'accepted' and application.user not in org.members:
            org.members.append(application.user)
            db.session.commit()
            flash(f'User {application.user.username} has been added to organization members', 'success')
        else:
            flash('Application status updated', 'success')
    
        return redirect(url_for('organization_applications', org_id=org.id))

    @app.route('/vacancy_application/<int:app_id>/update', methods=['POST'])
    @login_required
    def update_vacancy_application_status(app_id):
        application = Application.query.get_or_404(app_id)
        vacancy = application.vacancy
    
        # Проверка прав (только лидер организации или админы)
        if vacancy.organization.leader_id != current_user.id and current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('vacancy_details', vacancy_id=vacancy.id))
    
        new_status = request.form.get('status')
        if new_status not in ['accepted', 'rejected', 'pending']:
            flash('Invalid status', 'error')
            return redirect(url_for('vacancy_details', vacancy_id=vacancy.id))
    
        application.status = new_status
    
        # Если заявка принята, добавляем пользователя в члены организации
        if new_status == 'accepted' and application.user not in vacancy.organization.members:
            vacancy.organization.members.append(application.user)
    
        db.session.commit()
    
        flash(f'Application status updated to {new_status}', 'success')
        return redirect(url_for('vacancy_details', vacancy_id=vacancy.id))

    #organisations logic
    @app.route('/organization/<int:org_id>')
    def organization_public_details(org_id):
        org = Organization.query.get_or_404(org_id)
        events = Event.query.filter_by(organization_id=org_id).order_by(Event.date).all()
        vacancies = Vacancy.query.filter_by(organization_id=org_id).order_by(Vacancy.created_at.desc()).all()
        return render_template('organization_public_details.html', 
                             organization=org,
                             events=events,
                             vacancies=vacancies)

    @app.route('/organization/<int:org_id>/remove_member/<int:user_id>', methods=['POST'])
    @login_required
    def remove_member(org_id, user_id):
        org = Organization.query.get_or_404(org_id)
        user = User.query.get_or_404(user_id)
    
        # Проверка прав (только лидер организации или админы)
        if org.leader_id != current_user.id and current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('organization_details', org_id=org_id))
    
        if user in org.members:
            org.members.remove(user)
            db.session.commit()
            flash(f'User {user.username} has been removed from organization', 'success')
        else:
            flash('User is not a member of this organization', 'warning')
    
        return redirect(url_for('organization_details', org_id=org_id))




    #event logic
    @app.route('/event/<int:event_id>')
    def event_details(event_id):
        event = Event.query.get_or_404(event_id)
        organization = Organization.query.get(event.organization_id)
        return render_template('event_details.html', event=event, organization=organization)

    @app.route('/event/<int:event_id>/register', methods=['GET', 'POST'])
    @login_required
    def register_for_event(event_id):
        event = Event.query.get_or_404(event_id)
    
        # Проверяем, не зарегистрирован ли пользователь уже
        if current_user in event.registrations:
            flash('You are already registered for this event', 'warning')
            return redirect(url_for('event_details', event_id=event.id))
    
        if request.method == 'POST':
            # Регистрируем пользователя на событие
            event.registrations.append(current_user)
            db.session.commit()
        
            flash('You have successfully registered for this event!', 'success')
            return redirect(url_for('event_details', event_id=event.id))
    
        return render_template('register_for_event.html', event=event)
    
    @app.route('/event/<int:event_id>/registrations')
    @login_required
    def event_registrations(event_id):
        event = Event.query.get_or_404(event_id)
        organization = event.organization

        # Проверка прав
        if current_user.role not in ['root_admin', 'admin']:
            if not organization or current_user.id != organization.leader_id:
                flash('Access denied', 'error')
                return redirect(url_for('event_details', event_id=event.id))

        # Просто получаем всех зарегистрированных пользователей
        registrations = event.registrations  # Это уже список пользователей

        return render_template('event_registrations.html', 
                             event=event,
                             organization=organization,
                             registrations=registrations)


    @app.route('/event/<int:event_id>/edit', methods=['GET', 'POST'])
    @login_required
    def edit_event(event_id):
        event = Event.query.get_or_404(event_id)
        organization = Organization.query.get(event.organization_id)
    
        # Проверка прав (только админы или лидер организации)
        if current_user.role not in ['root_admin', 'admin'] and current_user.id != organization.leader_id:
            flash('Access denied', 'error')
            return redirect(url_for('event_details', event_id=event.id))

        if request.method == 'POST':
            event.title = request.form.get('title')
            date_str = request.form.get('date')
            event.description = request.form.get('description')
            event.organization_id = request.form.get('organization_id')
        
            try:
                event.date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                flash('Invalid date format', 'error')
                return redirect(url_for('edit_event', event_id=event.id))
        
            db.session.commit()
            flash('Event updated successfully!', 'success')
            return redirect(url_for('event_details', event_id=event.id))
    
        organizations = Organization.query.all()
        return render_template('edit_event.html', 
                             event=event,
                             organizations=organizations)

    @app.route('/event/<int:event_id>/delete', methods=['POST'])
    @login_required
    def delete_event(event_id):
        event = Event.query.get_or_404(event_id)
        organization = Organization.query.get(event.organization_id) if event.organization_id else None
    
        # Проверка прав (только админы или лидер организации)
        if current_user.role not in ['root_admin', 'admin']:
            if not organization or current_user.id != organization.leader_id:
                flash('Access denied', 'error')
                return redirect(url_for('event_details', event_id=event.id))

        db.session.delete(event)
        db.session.commit()
        flash('Event has been deleted', 'success')
        return redirect(url_for('events'))

    # Protected routes (require auth)
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
        username = request.form.get('username')
        email = request.form.get('email')

        if email != current_user.email:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email already registered by another user', 'error')
                return redirect(url_for('profile'))

        current_user.username = username
        current_user.email = email
        db.session.commit()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    @app.route('/change_password', methods=['POST'])
    @login_required
    def change_password():
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('profile'))

        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('profile'))

        current_user.password = generate_password_hash(new_password)
        db.session.commit()

        flash('Password changed successfully!', 'success')
        return redirect(url_for('profile'))

    # Organization leader routes
    @app.route('/my_organizations')
    @login_required
    def my_organizations():
        orgs = Organization.query.filter_by(leader_id=current_user.id).all()
        return render_template('my_organizations.html', organizations=orgs)

    @app.route('/my_organizations/<int:org_id>')
    @login_required
    def organization_details(org_id):
        org = Organization.query.get_or_404(org_id)
        
        if org.leader_id != current_user.id and current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
        
        events = Event.query.filter_by(organization_id=org_id).order_by(Event.date).all()
        vacancies = Vacancy.query.filter_by(organization_id=org_id).order_by(Vacancy.created_at.desc()).all()
        members = org.members
        
        return render_template('organization_details.html', 
                           organization=org,
                           events=events,
                           vacancies=vacancies,
                           members=members)

    @app.route('/create_event_for_org/<int:org_id>', methods=['GET', 'POST'])
    @login_required
    def create_event_for_org(org_id):
        org = Organization.query.get_or_404(org_id)
    
        if org.leader_id != current_user.id and current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            title = request.form.get('title')
            date_str = request.form.get('date')  # Будет в формате "YYYY-MM-DDTHH:MM"
            description = request.form.get('description')
        
            try:
                # Преобразуем из формата HTML5 datetime-local в Python datetime
                date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                flash('Invalid date format. Please use the calendar picker or format YYYY-MM-DDTHH:MM', 'error')
                return redirect(url_for('create_event_for_org', org_id=org_id))
        
            new_event = Event(
                title=title,
                date=date,
                description=description,
                organization_id=org_id
            )
        
            db.session.add(new_event)
            db.session.commit()
        
            flash('Event created successfully!', 'success')
            return redirect(url_for('organization_details', org_id=org_id))
        
        return render_template('create_event_for_org.html', organization=org)

    @app.route('/create_vacancy_for_org/<int:org_id>', methods=['GET', 'POST'])
    @login_required
    def create_vacancy_for_org(org_id):
        org = Organization.query.get_or_404(org_id)
        
        if org.leader_id != current_user.id and current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            title = request.form.get('title')
            description = request.form.get('description')
            
            new_vacancy = Vacancy(
                title=title,
                description=description,
                organization_id=org_id
            )
            
            db.session.add(new_vacancy)
            db.session.commit()
            
            flash('Vacancy created successfully!', 'success')
            return redirect(url_for('organization_details', org_id=org_id))
            
        return render_template('create_vacancy_for_org.html', organization=org)

    @app.route('/update_organization/<int:org_id>', methods=['POST'])
    @login_required
    def update_organization(org_id):
        org = Organization.query.get_or_404(org_id)
        
        if org.leader_id != current_user.id and current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
        
        description = request.form.get('description')
        org.description = description
        db.session.commit()
        
        flash('Organization updated successfully!', 'success')
        return redirect(url_for('organization_details', org_id=org_id))

    # Admin routes
    @app.route('/admin')
    @login_required
    def admin_panel():
        if current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
        return render_template('admin_panel.html')

    @app.route('/admin/users')
    @login_required
    def admin_users():
        if current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))

        users = User.query.order_by(User.id).all()
        return render_template('admin/users.html', users=users)

    @app.route('/admin/create_admin', methods=['GET', 'POST'])
    @login_required
    def create_admin():
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
                role='admin'
            )

            db.session.add(new_admin)
            db.session.commit()

            flash('New admin created successfully!', 'success')
            return redirect(url_for('admin_users'))

        return render_template('admin/create_admin.html')

    @app.route('/admin/create_organization', methods=['GET', 'POST'])
    @login_required
    def create_organization():
        if current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            name = request.form.get('name')
            description = request.form.get('description')
            leader_id = request.form.get('leader_id')
            
            new_org = Organization(
                name=name,
                description=description,
                leader_id=leader_id
            )
            
            db.session.add(new_org)
            db.session.commit()
            
            flash('Organization created successfully!', 'success')
            return redirect(url_for('organizations'))
            
        users = User.query.all()
        return render_template('admin/create_organization.html', users=users)

    @app.route('/admin/create_event', methods=['GET', 'POST'])
    @login_required
    def create_event():
        if current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            title = request.form.get('title')
            date_str = request.form.get('date')  # Формат: "YYYY-MM-DDTHH:MM"
            description = request.form.get('description')
            organization_id = request.form.get('organization_id')
        
            try:
                # Конвертируем из HTML5 datetime-local в Python datetime
                date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                flash('Invalid date format. Please use the calendar picker or enter in YYYY-MM-DDTHH:MM format (e.g. 2023-12-31T14:30)', 'error')
                return redirect(url_for('create_event'))
        
            new_event = Event(
                title=title,
                date=date,
                description=description,
                organization_id=organization_id
            )
        
            db.session.add(new_event)
            db.session.commit()
        
            flash('Event created successfully!', 'success')
            return redirect(url_for('events'))
        
        organizations = Organization.query.all()
        return render_template('admin/create_event.html', organizations=organizations)

    @app.route('/admin/create_vacancy', methods=['GET', 'POST'])
    @login_required
    def create_vacancy():
        if current_user.role not in ['root_admin', 'admin']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            title = request.form.get('title')
            description = request.form.get('description')
            organization_id = request.form.get('organization_id')
            
            new_vacancy = Vacancy(
                title=title,
                description=description,
                organization_id=organization_id
            )
            
            db.session.add(new_vacancy)
            db.session.commit()
            
            flash('Vacancy created successfully!', 'success')
            return redirect(url_for('vacancies'))
            
        organizations = Organization.query.all()
        return render_template('admin/create_vacancy.html', organizations=organizations)

    @app.route('/admin/promote_to_admin/<int:user_id>')
    @login_required
    def promote_to_admin(user_id):
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
        if current_user.role != 'root_admin':
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