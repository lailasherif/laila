from flask import Flask, render_template, request, flash, redirect, url_for
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from hashlib import md5
import calendar 



app = Flask(__name__)

app.config['SECRET_KEY'] = 'you-will-never-know'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'


db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    location = db.Column(db.String(50))
    password_hash = db.Column(db.String(80))
    date_created = db.Column(db.DateTime, default=datetime.now)
    bio = db.Column(db.String(100))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return '<User {}>'.format(self.username)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(digest, size)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Post {}>'.format(self.body)
        


     


class RegisterForm(FlaskForm):
    username = StringField('Username', render_kw={'placeholder': 'Please input Name'}, validators=[DataRequired()])    
    email = StringField('Email', render_kw={'placeholder': 'name@email.com'}, validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', render_kw={'placeholder': 'Please input Name'}, validators=[DataRequired()])    
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('remember me')
    submit = SubmitField('Sign Up')

@app.route("/")
def home():
    return "Hello Flask"

@app.route("/register", methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user is None:
            user = User(username=form.username.data, email=form.email.data) 
            user.set_password(form.password.data) 
            db.session.add(user)
            db.session.commit()
            login_user(user)
            # return '<h1>New user has been created!</h1>'
            return redirect(url_for('dashboard'))
        flash("A user already exists with that email address.")
    return render_template("register.html", title="Sign Up", form=form)

@app.route("/login", methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user is None or not existing_user.check_password(form.password.data):
            flash("Invalid username or password!")
            return render_template("login.html", form=form)
        login_user(existing_user, remember=form.remember_me.data)
        flash("Successful!")
        return redirect(url_for('dashboard'))
    return render_template("login.html", title="login", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/Welcome")
def Welcome():
    if current_user.is_authenticated:
        username = current_user.username
        location = current_user.location
        date_created = current_user.date_created
        bio = current_user.bio
        return "Username: " + username + "Location:" + location + "Date Joined:" + date_created + "Your Bio" + bio
    return "error. No current user logged in."


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/user/")
@app.route("/user/<username>")
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    # posts = Post.query.all()
    # posts = Post.query.filter_by(user_id=1)
    posts = [
        {'author': user, 'body': 'Test post #1'},
        {'author': user, 'body': 'Test post #2'}
    ]
    return render_template("user.html", user=user, posts=posts)

@app.route("/api/data")
def get_data():
    return app.send_static_file("data.json")

class GroupForm(FlaskForm):
    groupname = StringField('Group Name', unique=True, validators=[DataRequired()])
    bio = TextField('Tell Us About Your Group...')
    submit = SubmitField('Create Group')

class Event(db.Model):
    date = db.Column(db.Integer)
    groupname = db.Column(db.String(15), unique=True)
    time = db.Column(db.Integer)
    about = db.Column(db.String(100), unique=True)

class Group(db.Model):
    gropuname = db.Column(db.String(15), unique=True)
    date_created = db.Column(db.DateTime, default=datetime.now)
    bio = db.Column(db.String(100))


 
print([calendar.monthcalendar(datetime.now().year, month) for month in range(1, 13)])

if __name__ == "__main__":
    app.run(debug=True)

    
