from flask import render_template,Flask,request,redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, TextAreaField, PasswordField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import os

my_email = os.environ.get("MY_EMAIL")
password = os.environ.get("PASSWORD")


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    task = relationship("Tasks", back_populates="task_user")
    taskk = relationship("SelectedTask", back_populates="task_user")
    taskkk = relationship("CompletedTask", back_populates="task_user")


class Tasks(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    task_user = relationship("Users", back_populates="task")
    task_name = db.Column(db.String(100), nullable=False)
    task_description = db.Column(db.String, nullable=False)


class SelectedTask(db.Model):
    __tablename__ = "selectedtasks"
    id = db.Column(db.Integer, primary_key=True)
    task_user = relationship("Users", back_populates="taskk")
    selected_task_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    task_name = db.Column(db.String(100), nullable=False)
    task_description = db.Column(db.String, nullable=False)


class CompletedTask(db.Model):
    __tablename__ = "completedtasks"
    id = db.Column(db.Integer, primary_key=True)
    task_user = relationship("Users", back_populates="taskkk")
    completed_task_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    task_name = db.Column(db.String(100), nullable=False)
    task_description = db.Column(db.String, nullable=False)


class TaskForm(FlaskForm):
    task_title = StringField("Task Name:", validators=[DataRequired()])
    task_description = StringField("Task Description", validators=[DataRequired()])
    add_task = SubmitField("Add Task")

class ContactForm(FlaskForm):
    name = StringField(validators=[DataRequired()])
    email = EmailField(validators=[DataRequired()])
    message = TextAreaField(validators=[DataRequired()])
    submit = SubmitField("Send Message")

class RegisterForm(FlaskForm):
    username = StringField("Username: ", validators=[DataRequired()])
    email = EmailField("Email:", validators=[DataRequired()])
    password = PasswordField("Password:", validators=[DataRequired()])
    add_user = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField("Username: ", validators=[DataRequired()])
    password = PasswordField("Password:", validators=[DataRequired()])
    add_user = SubmitField("Register")


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = request.form.get("email")
        if Users.query.filter_by(email=email).first():
            flash("The user already exists")
            return redirect(url_for('login'))
        password = generate_password_hash(request.form.get("password"), method="sha256", salt_length=5)
        new_user = Users(
            email=request.form.get("email"),
            password=password,
            username=request.form.get("username")
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('login'))
    return render_template("register.html", form=form)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST":
        curr_user = Users.query.filter_by(username=form.username.data).first()
        if curr_user:
            if check_password_hash(curr_user.password, form.password.data):
                login_user(curr_user)
                return redirect(url_for('home'))
            else:
                flash("The password entered is incorrect")
        else:
            flash("The user doesnt exist")
    return render_template("login.html", form=form)


@app.route('/main')
@login_required
def home():
    tasks = Tasks.query.all()
    selected_tasks = SelectedTask.query.all()
    completed_tasks = CompletedTask.query.all()
    return render_template('index.html', tasks=tasks, selected_task=selected_tasks, completed_tasks=completed_tasks)


@app.route('/logout', methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('mainpage'))


@app.route('/add-task', methods=["GET", "POST"])
@login_required
def add_task():
    form = TaskForm()
    if form.validate_on_submit():
        new_task = Tasks(
            task_name=form.task_title.data,
            task_description=form.task_description.data,
            task_user=current_user
        )
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('task.html', form=form)


@app.route('/select/<int:task_id>')
@login_required
def select_task(task_id):
    selected_task = Tasks.query.get(task_id)
    add_selected_task = SelectedTask(
        task_name=selected_task.task_name,
        task_description=selected_task.task_description,
        task_user=current_user
    )
    db.session.add(add_selected_task)
    db.session.delete(selected_task)
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/complete/<int:task_id>')
@login_required
def complete_task(task_id):
    completed_task = SelectedTask.query.get(task_id)
    add_completed_task = CompletedTask(
        task_name=completed_task.task_name,
        task_description=completed_task.task_description,
        task_user=current_user
    )
    db.session.add(add_completed_task)
    db.session.delete(completed_task)
    db.session.commit()
    return redirect(url_for('home'))


@app.route("/delete/<int:task_id>")
@login_required
def delete_task(task_id):
    task_to_delete = Tasks.query.get(task_id)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


@app.route("/delete_selected/<int:task_id>")
@login_required
def delete_selected_task(task_id):
    task_to_delete = SelectedTask.query.get(task_id)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


@app.route("/delete_completed/<int:task_id>")
@login_required
def delete_completed_task(task_id):
    task_to_delete = CompletedTask.query.get(task_id)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/support')
def support():
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        message = form.message.data
        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(user=my_email, password=password)
            connection.sendmail(
                from_addr=my_email,
                to_addrs="aumbattul99@gmail.com",
                msg=f"Subject:Someone wants to contact you.."
                    f"\n\nName: {name}"
                    f"\n\nEmail: {email}"
                    f"\n\nMessage: {message}"
            )
            form.name.data = ""
            form.email.data = ""
            form.message.data = ""
            return render_template('contact.html', form=form)
    return render_template('contact.html', form=form)

@app.route('/')
def mainpage():
    return render_template('home.html')




#
#
# with app.app_context():
#     db.create_all()


if __name__ == "__main__":
    app.run(debug=True)