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

class Categories(db.Model):
    __tablename__ = 'category'

    category_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    category_name = db.Column(db.String(50), nullable=False, unique=True)


class Quizzes(db.Model):
    __tablename__ = 'quizzes'

    quiz_id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.category_id'), nullable = False)
    total_questions = db.Column(db.Integer)
    time_limit = db.Column(db.Integer)

class Questions(db.Model):
    __tablename__ = 'questions'

    question_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.quiz_id'), nullable=False)
    question_text = db.Column(db.String(500), nullable=False)

    options = db.relationship(
        'Options',
        backref='question',
        cascade='all, delete',
        lazy=True
    )



class Options(db.Model):
    __tablename__ = 'options'

    option_id = db.Column(db.Integer, primary_key = True)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.question_id'), nullable = False)
    option_text = db.Column(db.String(255), nullable = False)
    is_correct = db.Column(db.Boolean, default = False, nullable = False)

class Results(db.Model):
    __tablename__ = 'results'

    result_id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.student_id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.quiz_id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
