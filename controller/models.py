from controller.database import db

class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    username = db.Column(db.String(80), unique = True, nullable = False)
    email = db.Column(db.String(120), unique = True, nullable = False)
    password_hash = db.Column(db.String(128), nullable = False)

    roles = db.relationship('Role', secondary = 'user_role', backref = db.backref('users', lazy = True, uselist = False))
    student_details = db.relationship('Student', backref = 'user', lazy = True, uselist = False)
    staff_details = db.relationship('Staff', backref = 'user', lazy = True, uselist = False)

class Role(db.Model):
    __tablename__ = 'role'
    role_id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    name = db.Column(db.String(50), nullable = False)

class UserRole(db.Model):
    __tablename__ = 'user_role'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable = False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.role_id'), nullable = False)

class Staff(db.Model):
    __tablename__ = 'staff'

    staff_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    flag = db.Column(db.Boolean, default=False)  # ✅ ADD THIS


class Student(db.Model):
    __tablename__ = 'student'

    student_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    flag = db.Column(db.Boolean, default=False)


