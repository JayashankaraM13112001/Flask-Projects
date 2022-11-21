from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import webbrowser

app=Flask(__name__)
app.app_context().push()
app.config['SECRET_KEY']='Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///database.db'
bootstrap=Bootstrap(app)
db=SQLAlchemy(app)

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'


class User(UserMixin, db.Model):
    id=db.Column(db.Integer, primary_key = True)
    username=db.Column(db.String(15), unique = True)
    email=db.Column(db.String(50), unique = True)
    password=db.Column(db.String(80))


class Link(db.Model):
    id=db.Column(db.Integer, primary_key = True)
    username=db.Column(db.String(15))
    linkname=db.Column(db.String(50))
    linkurl=db.Column(db.String(200))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username=StringField('Username', validators = [InputRequired(), Length(min = 4, max = 15)])
    password=PasswordField('Password', validators = [InputRequired(), Length(min = 8, max = 80)])
    remember=BooleanField('Remember me')


class RegisterForm(FlaskForm):
    email=StringField('Email', validators = [InputRequired(), Email(message = 'Invalid email'), Length(max = 50)])
    username=StringField('Username', validators = [InputRequired(), Length(min = 4, max = 15)])
    password=PasswordField('Password', validators = [InputRequired(), Length(min = 8, max = 80)])


class AddLinkForm(FlaskForm):
    linkname=StringField('Linkname', validators = [InputRequired(), Length(max = 50)])
    linkurl=StringField('Linkurl', validators = [InputRequired(), Length(max = 200)])


class EditLinkForm(FlaskForm):
    link_name=StringField('Linkname', validators = [InputRequired(), Length(max = 50)])
    link_url=StringField('Linkurl', validators = [InputRequired(), Length(max = 200)])


class SerachTreeForm(FlaskForm):
    treename=StringField('Treename', validators = [InputRequired(), Length(min = 4)])


@app.route('/', methods = ['GET', 'POST'])
def index():
    form=SerachTreeForm()
    if form.validate_on_submit():
        tree=Link.query.filter_by(username = form.treename.data).first()
        if tree:
            links=Link.query.filter_by(username = form.treename.data).all()
            return render_template('print_tree.html', links = links, name = form.treename.data)
        else:
            return render_template('index.html', error_msg = "No data exist", form = form)

    return render_template('index.html', form = form)


@app.route('/login', methods = ['GET', 'POST'])
def login():
    form=LoginForm()

    if form.validate_on_submit():
        user=User.query.filter_by(username = form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember = form.remember.data)
                return redirect(url_for('dashboard'))
        error_msg="Invalid username or password"
        return render_template('login.html', form = form, error_msg = error_msg)
        # return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form = form)


@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    form=RegisterForm()

    if form.validate_on_submit():
        hashed_password=generate_password_hash(form.password.data, method = 'sha256')
        new_user=User()
        new_user.username=form.username.data
        new_user.email=form.email.data
        new_user.password=hashed_password
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
        # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form = form)


@app.route('/links_list')
@login_required
def links_list():
    links=Link.query.filter_by(username = current_user.username).all()
    return render_template('links_list.html', links = links, name = current_user.username)


@app.route('/add_link', methods = ['GET', 'POST'])
@login_required
def add_link():
    form=AddLinkForm()
    if form.validate_on_submit():
        new_link=Link(username = current_user.username, linkname = form.linkname.data, linkurl = form.linkurl.data)
        db.session.add(new_link)
        db.session.commit()

        return redirect(url_for('links_list'))

    return render_template('add_link.html', form = form)


@app.route('/delete/<lid>', methods = ['GET', 'POST'])
@login_required
def delete(lid):
    if lid:
        Link.query.filter_by(id = lid).delete()
        db.session.commit()
        return redirect(url_for('links_list'))
    else:
        return redirect(url_for('add_link'))


@app.route('/edit/<lid>',methods=['GET','POST'])
@login_required
def edit(lid):
    form=EditLinkForm()
    lnk=Link.query.filter_by(id = lid).first()
    if form.validate_on_submit():
        lnk.linkname=form.link_name.data
        lnk.linkurl=form.link_url.data
        db.session.commit()
        return redirect(url_for('links_list'))
    return render_template('edit_link.html',form=form,llid=lid)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name = current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"]="no-cache, no-store, must-revalidate"
    return response


if __name__=='__main__':
    with app.app_context():
        db.create_all()
        app.run(debug = True)
