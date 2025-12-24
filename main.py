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

@app.route('/create-quiz', methods=['GET', 'POST'])
def create_quiz():
    if 'user_id' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))

    if request.method == 'POST':
        category_name = request.form.get('category')
        time_limit = request.form.get('time_limit')

        # Category
        category = Categories.query.filter_by(category_name=category_name).first()
        if not category:
            category = Categories(category_name=category_name)
            db.session.add(category)
            db.session.commit()

        # Create Quiz
        quiz = Quizzes(
            category_id=category.category_id,
            time_limit=time_limit,
            total_questions=0
        )
        db.session.add(quiz)
        db.session.commit()

        # store quiz_id in session
        session['quiz_id'] = quiz.quiz_id

        return redirect(url_for('add_questions'))

    return render_template('create_quiz.html')

@app.route('/add-questions', methods=['GET', 'POST'])
def add_questions():
    if 'quiz_id' not in session:
        return redirect(url_for('staff_dashboard'))

    if request.method == 'POST':
        quiz_id = session['quiz_id']

        questions = request.form.getlist('question[]')
        opt1 = request.form.getlist('opt1[]')
        opt2 = request.form.getlist('opt2[]')
        opt3 = request.form.getlist('opt3[]')
        opt4 = request.form.getlist('opt4[]')
        correct = request.form.getlist('correct[]')

        for i in range(len(questions)):
            q = Questions(quiz_id=quiz_id, question_text=questions[i])
            db.session.add(q)
            db.session.commit()

            options = [opt1[i], opt2[i], opt3[i], opt4[i]]

            for idx, text in enumerate(options, start=1):
                db.session.add(
                    Options(
                        question_id=q.question_id,
                        option_text=text,
                        is_correct=(str(idx) == correct[i])
                    )
                )

            db.session.commit()

        return redirect(url_for('finish_quiz'))

    return render_template('add_questions.html')




@app.route('/finish-quiz')
def finish_quiz():
    quiz_id = session.pop('quiz_id', None)

    if quiz_id:
        quiz = db.session.get(Quizzes, quiz_id)
        quiz.total_questions = Questions.query.filter_by(quiz_id=quiz_id).count()
        db.session.commit()

    flash('Quiz uploaded successfully!', 'success')
    return redirect(url_for('staff_dashboard'))  # ✅ STAFF DASHBOARD


@app.route('/view-quiz', methods=['GET', 'POST'])
def view_quiz():
    if 'user_id' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))

    categories = Categories.query.all()

    if request.method == 'POST':
        category_id = request.form.get('category')
        return redirect(url_for('list_quizzes', category_id=category_id))

    return render_template('view_quiz.html', categories=categories)

@app.route('/list-quizzes/<int:category_id>')
def list_quizzes(category_id):
    if 'user_id' not in session or session.get('role') != 'staff':
        return redirect(url_for('login'))

    quizzes = Quizzes.query.filter_by(category_id=category_id).all()
    category = Categories.query.get(category_id)

    return render_template(
        'list_quizzes.html',
        quizzes=quizzes,
        category=category
    )

@app.route('/delete-quiz/<int:quiz_id>')
def delete_quiz(quiz_id):
    if session.get('role') != 'staff':
        return redirect(url_for('login'))

    questions = Questions.query.filter_by(quiz_id=quiz_id).all()
    for q in questions:
        Options.query.filter_by(question_id=q.question_id).delete()
        db.session.delete(q)

    quiz = db.session.get(Quizzes, quiz_id)
    if quiz:
        db.session.delete(quiz)
        db.session.commit()

    flash('Quiz deleted successfully!', 'success')
    return redirect(url_for('staff_dashboard'))  # ✅ STAFF DASHBOARD



@app.route('/delete-question/<int:question_id>')
def delete_question(question_id):
    Options.query.filter_by(question_id=question_id).delete()
    Questions.query.filter_by(question_id=question_id).delete()
    db.session.commit()

    flash('Question deleted successfully!', 'success')
    return redirect(url_for('staff_dashboard'))  # ✅ STAFF DASHBOARD




@app.route('/edit-quiz/<int:quiz_id>', methods=['GET', 'POST'])
def edit_quiz(quiz_id):
    quiz = db.session.get(Quizzes, quiz_id)
    questions = Questions.query.filter_by(quiz_id=quiz_id).all()

    if request.method == 'POST':
        for q in questions:
            q.question_text = request.form.get(f'question_{q.question_id}')
            correct = request.form.get(f'correct_{q.question_id}')

            for opt in q.options:
                opt.option_text = request.form.get(f'option_{opt.option_id}')
                opt.is_correct = str(opt.option_id) == correct

        db.session.commit()
        flash('Quiz updated successfully!', 'success')

        return redirect(url_for('staff_dashboard'))  # ✅ STAFF DASHBOARD

    return render_template('edit_quiz_questions.html', quiz=quiz, questions=questions)



@app.route('/take-test', methods=['GET', 'POST'])
def take_test():
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect(url_for('login'))

    categories = Categories.query.all()

    if request.method == 'POST':
        category_id = request.form.get('category')
        return redirect(url_for('select_quiz', category_id=category_id))

    return render_template('take_test.html', categories=categories)

@app.route('/select-quiz/<int:category_id>')
def select_quiz(category_id):
    quizzes = Quizzes.query.filter_by(category_id=category_id).all()
    return render_template('select_quiz.html', quizzes=quizzes)

@app.route('/start-test/<int:quiz_id>', methods=['GET', 'POST'])
def start_test(quiz_id):
    questions = Questions.query.filter_by(quiz_id=quiz_id).all()

    if request.method == 'POST':
        score = 0
        for q in questions:
            selected = request.form.get(str(q.question_id))
            correct = Options.query.filter_by(
                question_id=q.question_id,
                is_correct=True
            ).first()

            if correct and selected == str(correct.option_id):
                score += 1

        student = Student.query.filter_by(user_id=session['user_id']).first()
        db.session.add(Results(
            student_id=student.student_id,
            quiz_id=quiz_id,
            score=score,
            total_questions=len(questions)
        ))
        db.session.commit()

        flash(f'Test completed! Score: {score}/{len(questions)}', 'success')
        return redirect(url_for('student_dashboard'))  # ✅ STUDENT DASHBOARD

    return render_template('start_test.html', questions=questions)


@app.route('/my-results')
def my_results():
    if session.get('role') != 'student':
        return redirect(url_for('login'))

    user_id = session.get('user_id')

    results = (
        db.session.query(Results, Quizzes, User)
        .join(Student, Results.student_id == Student.student_id)
        .join(User, Student.user_id == User.user_id)
        .join(Quizzes, Results.quiz_id == Quizzes.quiz_id)
        .filter(User.user_id == user_id)
        .all()
    )

    return render_template('my_results.html', results=results)


@app.route('/student-results')
def student_results():
    results = db.session.query(
        Results, User.username, User.user_id
    ).join(Student, Results.student_id == Student.student_id)\
     .join(User, Student.user_id == User.user_id).all()

    return render_template('student_results.html', results=results)

@app.route('/manage-students')
def manage_students():
    if session.get('role') != 'staff':
        return redirect(url_for('login'))

    students = (
        db.session.query(Student, User)
        .join(User, Student.user_id == User.user_id)
        .all()
    )

    return render_template('manage_students.html', students=students)

@app.route('/edit-student/<int:user_id>', methods=['GET', 'POST'])
def edit_student(user_id):
    if session.get('role') != 'staff':
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        db.session.commit()

        flash('Student updated successfully!', 'success')
        return redirect(url_for('manage_students'))

    return render_template('edit_student.html', user=user)

@app.route('/delete-student/<int:user_id>')
def delete_student(user_id):
    if session.get('role') != 'staff':
        return redirect(url_for('login'))

    student = Student.query.filter_by(user_id=user_id).first()
    if not student:
        flash('Student not found', 'danger')
        return redirect(url_for('manage_students'))

    # delete results
    Results.query.filter_by(student_id=student.student_id).delete()

    # delete student profile
    db.session.delete(student)

    # delete user
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)

    db.session.commit()
    flash('Student deleted successfully!', 'success')

    return redirect(url_for('manage_students'))



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))



if __name__ == "__main__":
    app.run()