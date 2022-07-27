from flask import Flask, render_template, redirect, url_for, flash, send_from_directory
from flask_bootstrap import Bootstrap
from flask_gravatar import Gravatar
from flask_sqlalchemy import SQLAlchemy
from flask_ckeditor import CKEditor
from datetime import datetime
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, ForeignKey
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from form import CreatePostForm, LoginForm, RegisterForm, CommentForm
from functools import wraps
from flask import abort, request, redirect, url_for
import os


# CONNECT TO FLASK
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['CKEDITOR_PKG_TYPE'] = 'standard'
ckeditor = CKEditor(app)
Bootstrap(app)

secretkey = '8BYkEfBA6O6donzWlSihBXox7C0sK'
# LOAD GRAVATAR BY INITIALIZING
gravatar = Gravatar(app, size=50, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blogs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# set up flask login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'Login'


# PARENT
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # USER CAN HAVE MANY BLOG POSTS and COMMENTS
    posts = db.relationship('BlogPost', back_populates='author')
    # "comment_author" refers to the comment_author property in the Comment class.
    comments = db.relationship('Comment', back_populates='comment_author')


# CHILD
class BlogPost(db.Model):
    __tablename__ = 'blog_post'
    id = db.Column(db.Integer, primary_key=True)
    # foreign key assignments
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # Create reference to the User object, the "posts" refers to the post property in the User class.
    author = db.relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # a single blog post can have multiple comments
    comments = db.relationship('Comment', back_populates='parent_post')


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # *******Add child relationship*******#
    # "users.id" The users refers to the tablename of the Users class.
    # "comments" refers to the comment's property in the User class.
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_author = db.relationship('User', back_populates='comments')
    # creating a foreign key for every comment to link the blogpost
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'))
    parent_post = db.relationship('BlogPost', back_populates='comments')


db.create_all()


@app.route('/')
def get_all_posts():
    all_posts = BlogPost.query.all()
    print(all_posts)
    return render_template("index.html", all_posts=all_posts, logged_in=current_user.is_authenticated)


# set up the user loader.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data
        user = User.query.filter_by(email=email).first()

        # if the user email does not exist.
        if not user:
            flash('Your email does not exist. Try again.')
            return redirect(url_for('login'))

        # incorrect password.
        elif not check_password_hash(user.password, password):
            flash('Password is incorrect. Try again.')
            return redirect(url_for('login'))

        # finally both email and password works.
        else:
            login_user(user)
            flash('login successful.')
            return redirect(url_for('get_all_posts', logged_in=True))

    return render_template('login.html', login_form=login_form, logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        # check the database to be sure that the email isn't already at the database. if yes, proceed to login.
        if User.query.filter_by(email=register_form.email.data).first():
            flash('Email already exist. Use another email account')
            return redirect(url_for('login'))
        # if email not already in database, proceed to register and store data in database.
        else:
            insecure_password = register_form.password.data
            secure_password = generate_password_hash(insecure_password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(
                name=register_form.name.data,
                email=register_form.email.data,
                password=secure_password
            )
            db.session.add(new_user)
            db.session.commit()
            # proceed .to login page to authenticate the user.
            return redirect(url_for('login'))

    return render_template('register.html', register_form=register_form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


@app.route("/post/<post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    logged_in = current_user.is_authenticated
    if comment_form.validate_on_submit():
        if logged_in:
            new_comment = Comment(
                text=comment_form.comment.data,
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash('Unauthorized. Pls proceed to login or register to comment.')
            redirect(url_for('login'))

    return render_template("post.html", post=requested_post,
                           comment_form=comment_form, current_user=current_user,
                           logged_in=current_user.is_authenticated)


@app.route('/new_post', methods=['GET', 'POST'])
@admin_only
def new_post():
    form = CreatePostForm()
    date = datetime.now()
    if form.validate_on_submit():
        print('True')
        fresh_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            author_id=current_user.id,
            img_url=form.img_url.data,
            body=form.body.data,
            date=f'{date.strftime("%B")} {date.strftime("%d")}, {date.strftime("%Y")}'
        )
        db.session.add(fresh_post)
        db.session.commit()
        return redirect(url_for('get_all_posts'))

    return render_template('make-post.html', form=form, logged_in=current_user.is_authenticated)


@app.route('/edit-post/<post_id>', methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post_to_edit = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post_to_edit.title,
        subtitle=post_to_edit.subtitle,
        img_url=post_to_edit.img_url,
        author=post_to_edit.author,
        body=post_to_edit.body,
    )
    if edit_form.validate_on_submit():
        post_to_edit.title = edit_form.title.data
        post_to_edit.subtitle = edit_form.subtitle.data
        post_to_edit.author = edit_form.author.data
        post_to_edit.img_url = edit_form.img_url.data
        post_to_edit.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_to_edit.id))

    return render_template('make-post.html', form=edit_form, edit=True, logged_in=current_user.is_authenticated)


@app.route('/delete/<post_id>')
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True)
