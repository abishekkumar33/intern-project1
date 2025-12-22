from flask import Flask , render_template, session, redirect, request, url_for, flash
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from controller.config import Config
from controller.database import db
from controller.models import *

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()

    # ----- ROLES -----
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        admin_role = Role(name='admin')
        db.session.add(admin_role)

    staff_role = Role.query.filter_by(name='staff').first()
    if not staff_role:
        staff_role = Role(name='staff')
        db.session.add(staff_role)

    student_role = Role.query.filter_by(name='student').first()
    if not student_role:
        student_role = Role(name='student')
        db.session.add(student_role)

    db.session.commit()

    # ----- ADMIN USER -----
    admin_user = User.query.filter_by(username='QMA_ADMIN').first()
    if not admin_user:
        admin_user = User(
            username='QMA_ADMIN',
            email='admin@qma.com',
            password_hash=generate_password_hash('123456')
        )
        admin_user.roles.append(admin_role)
        db.session.add(admin_user)
        db.session.commit()



@app.route("/")
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))

        # Get user role
        role = user.roles[0].name  # admin / staff / student

        # Store session
        session['user_id'] = user.user_id
        session['role'] = role
        session['username'] = user.username


        # Role-based redirect
        if role == 'staff':
            return redirect(url_for('staff_dashboard'))

        elif role == 'student':
            return redirect(url_for('student_dashboard'))  # create later

        else:
            return redirect(url_for('home'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        role = request.form.get('role')
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')  # ✅ FIXED

        if not all([role, name, email, password, confirm]):
            flash('Please fill out all required fields', 'warning')
            return redirect(url_for('register'))

        if password != confirm:
            flash('Passwords do not match', 'warning')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'warning')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        new_user = User(
            username=name,
            email=email,
            password_hash=hashed_pw
        )

        db.session.add(new_user)
        db.session.commit()  # user_id generated here

        role_obj = Role.query.filter_by(name=role).first()
        new_user.roles.append(role_obj)
        db.session.commit()  # ✅ IMPORTANT

        if role == 'student':
            profile = Student(user_id=new_user.user_id, flag=False)
        else:
            profile = Staff(user_id=new_user.user_id, flag=False)

        db.session.add(profile)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/staff-dashboard')
def staff_dashboard():
    if 'user_id' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))
    return render_template('staff_dashboard.html')

@app.route('/student-dashboard')
def student_dashboard():
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect(url_for('login'))
    return render_template('student_dashboard.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run()