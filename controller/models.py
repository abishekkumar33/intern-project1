from controller.database import db

class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    username = db.Column(db.String(80), unique = True, nullable = False)
    email = db.Column(db.String(120), unique = True, nullable = False)
    password_hash = db.Column(db.String(128), nullable = False)

class Role(db.Model):
    __tablename__ = 'role'
    role_id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    name = db.Column(db.String(50), nullable = False)

class UserRole(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))
    role_id = db.Column(db.Integer, db.ForeignKey('role.role_id'))

