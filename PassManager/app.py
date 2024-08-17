from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import random
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'PehlaProject'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


# Define the Password model
class Password(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    notes = db.Column(db.String(500), nullable=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))


# Create all the database tables
with app.app_context():
    db.create_all()


def generate_password(length, lowercase_letters=True, uppercase_letters=True, numbers=True, special_characters=True):
    characters = ""
    if lowercase_letters:
        characters += string.ascii_lowercase
    if uppercase_letters:
        characters += string.ascii_uppercase
    if numbers:
        characters += string.digits
    if special_characters:
        characters += string.punctuation

    pwd = ""
    meets_criteria = False

    while not meets_criteria or len(pwd) < length:
        pwd = "".join(random.choice(characters) for _ in range(length))
        meets_criteria = True

        if lowercase_letters and not any(char.islower() for char in pwd):
            meets_criteria = False
        if uppercase_letters and not any(char.isupper() for char in pwd):
            meets_criteria = False
        if numbers and not any(char.isdigit() for char in pwd):
            meets_criteria = False
        if special_characters and not any(char in string.punctuation for char in pwd):
            meets_criteria = False

    return pwd

@app.route('/')
def landing():
    if current_user.is_authenticated:
        return render_template('index.html', user=current_user)
    else:
        return render_template('landing.html', user=current_user)
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                return redirect(url_for('hello_world'))
            else:
                
                flash('Incorrect email and/or password, try again.', 'error')
        else:
            flash('Incorrect email and/or password, try again.', 'error')
    return render_template("login.html", user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('landing'))


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', 'error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', 'error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', 'error')
        elif password1 != password2:
            flash('Passwords don\'t match.', 'error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', 'error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', 'success')
            return redirect(url_for('hello_world'))
    return render_template("sign_up.html", user=current_user)


@app.route('/hello_world', methods=['GET', 'POST'])
@login_required
def hello_world():
    if request.method == 'POST':
        url = request.form['url']
        notes = request.form['notes']
        length = int(request.form['length'])
        lowercase = 'lowercase' in request.form
        uppercase = 'uppercase' in request.form
        numbers = 'numbers' in request.form
        special = 'special' in request.form
        if not (length and (lowercase or uppercase or numbers or special)):
            flash('Please select at least one option and enter the length.', 'error')
        else:
            password = generate_password(length, lowercase, uppercase, numbers, special)
            password_entry = Password(url=url, password=password, notes=notes, user_id=current_user.id)
            db.session.add(password_entry)
            db.session.commit()
            flash('Password generated and saved successfully!', 'success')
            return redirect(url_for('passwords'))

    return render_template('index.html', user=current_user)


@app.route('/passwords', methods=['GET', 'POST'])
@login_required
def passwords():
    if request.method == 'POST':
        search_term = request.form['search']
        allPasswords = Password.query.filter(Password.url.ilike(f'%{search_term}%')).all()
    else:
        allPasswords = Password.query.filter_by(user_id=current_user.id).all()

    return render_template('passwords.html', allPasswords=allPasswords, user=current_user)


@app.route('/update/<int:sno>', methods=['GET', 'POST'])
@login_required
def update(sno):
    password_obj = Password.query.filter_by(sno=sno).first()
    if not password_obj:
        flash('Password not found.', 'error')
        return redirect(url_for('passwords'))

    if request.method == 'POST':
        url = request.form['url']
        password_value = request.form['password']
        notes = request.form['notes']
        password_obj.url = url
        password_obj.password = password_value
        password_obj.notes = notes
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('passwords'))

    return render_template('update.html', password=password_obj, user=current_user)


@app.route('/delete/<int:sno>')
@login_required
def delete(sno):
    password_obj = Password.query.filter_by(sno=sno).first()
    if not password_obj:
        flash('Password not found.', 'error')
    else:
        db.session.delete(password_obj)
        db.session.commit()
        flash('Password deleted successfully!', 'success')

    return redirect(url_for('passwords'))


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
