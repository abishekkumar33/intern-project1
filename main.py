from flask import Flask , render_template, session, redirect, request, url_for, flash
from werkzeug.security import generate_password_hash
from controller.config import Config
from controller.database import db
from controller.models import *

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()
    admin_role = Role.query.filter_by(name = 'admin').first()
    if not admin_role:
        admin_role = Role(name = 'admin')
        db.session.add(admin_role)

    staff_role = Role.query.filter_by(name = 'staff').first()
    if not staff_role:
        staff_role = Role(name = 'staff')
        db.session.add(staff_role)

    student_role = Role.query.filter_by(name = 'student').first()
    if not student_role:
        student_role = Role(name = 'student')
        db.session.add(student_role)
    db.session.commit()


    admin_user = User.query.filter_by(username = 'QMA_ADMIN').first()
    if not admin_user:
        admin_user = User(
            username = 'QMA_ADMIN',
            email = 'admin@qma.com',
            password_hash = '123456',
            roles = [admin_role]
        )
        
        db.session.add(admin_user)
    db.session.commit()

@app.route("/")
def home():
    return render_template('home.html')

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/register', methods = ['GET', 'POST'])
def register():
    if request.method == 'POST':
        print('In post method')
        role = request.form.get('role')
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')


        if not (role and name and email and password and confirm):
            flash('Please fill out all required fields', 'warning')
            return redirect(url_for('register'))
        if password != confirm:
            flash('Password do not match', 'warning')
            return redirect(url_for('register'))
        

        if User.query.filter_by(email = email).first():
            flash('Email already registered', 'warning')
            return redirect(url_for('register'))
        
        print('From frontend read')
        hashed_pw = generate_password_hash(password)
        new_user= User(username = name, email = email, password_hash = hashed_pw)
        print(new_user)
        db.session.add(new_user)
        db.session.commit()


        role_obj = Role.query.filter_by(name = role).first()
        if not role_obj:
            role_obj = Role(name = role)
            db.session.add(role_obj)
            db.session.commit()
        new_user.roles.append(role_obj)


        if role == 'student':
            profile = Student(user_id = new_user.user_id,
                              flag = False)
            
        else:
            profile = Staff(user_id = new_user.user_id,
                            flag = False)
        db.session.add(profile)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run()