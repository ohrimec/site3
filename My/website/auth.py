from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from .models import Note
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth', __name__)



@auth.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                flash('Logged in succesfully!', category='success')
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')


    return render_template('/login.html')

@auth.route('/sign-up', methods=['POST', 'GET'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exist.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')

        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')

        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')

        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('Account created!')
            return redirect(url_for('views.home'))
    return render_template('sign-up.html')

@auth.route('/user', methods=['POST', 'GET'])
def user():
    return render_template("user.html", user=current_user)


@auth.route('/notes', methods=['POST', 'GET'])
def notes():
    if request.method == 'POST':
        date = request.form.get('date')
        data = request.form.get('data')
        user_id = request.form.get('user_id')

        note = Note.query.filter_by(date=date).first()
        if note:
            flash('Note created')
        else:
            new_note = Note(date=date, data=data, user_id=user_id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note created')
            return redirect(url_for('auth.user'))
    return render_template('/notes.html')

