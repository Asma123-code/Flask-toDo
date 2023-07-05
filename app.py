from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = '2b76cb07ff2efcdccd9410bd9fbadde8'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sql'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)  # Initialize LoginManager

# Define the login view for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(150),unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    todos = db.relationship('Todo', backref='user')

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    complete = db.Column(db.Boolean, default=False)
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer,db.ForeignKey(User.id))

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        email = request.form.get('email')
        password = request.form.get('password')
    
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password,password):
                flash('You have logged in successfully!',category='success')
                login_user(user,remember=True)
                return redirect(url_for('home'))
            else:
                flash('Incorrect credentials,try again!',category='error')
        else:
            flash('Incorrect email-Id,try again!',category='error')
    return render_template("login.html",user=current_user) 

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('User already exists.', category='error')        
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 3:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash("Passwords don't match.", category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('home'))
    return render_template("sign_up.html", user=current_user)
 

@app.route('/home')
def home():
    if current_user.is_authenticated:
        todo_list = Todo.query.all()
    #todo_list =Todo.query.filter_by(user_id=current_user.id).all()
    #print(todo_list)
    return render_template('home.html', user=current_user, todo_list=todo_list)
    #return render_template("home.html",) 

@app.route('/')
def index():
        # Check if the user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    return render_template('login.html')



@app.route("/add", methods=["POST"])
def add():
    title = request.form.get("title")

    # Check if the title is empty
    if not title:
        flash("Title cannot be empty", "error")
        return redirect(url_for("index"))

    new_todo = Todo(title=title, complete=False)
    db.session.add(new_todo)
    db.session.commit()
    return redirect(url_for("index"))


@app.route("/update/<int:todo_id>")
def update(todo_id):
    todo =  Todo.query.filter_by(id=todo_id).first()
    todo.complete = not todo.complete
    db.session.commit()
    return redirect(url_for("index"))


@app.route("/delete/<int:todo_id>")
def delete(todo_id):
    todo =  Todo.query.filter_by(id=todo_id).first()
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for("index"))

    
 

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)