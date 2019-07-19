# YTCTF Platform API
# Copyright © 2019 Evgeniy Filimonov <evgfilim1@gmail.com>
# See full NOTICE at http://github.com/YummyTacos/YTCTF-API

from flask_mail import Message
from flask_sqlalchemy import SQLAlchemy

from app import app
from utils import check_password, hash_password

db = SQLAlchemy(app)


class IDMixin:
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)


class User(db.Model, IDMixin):
    username = db.Column(db.String(), unique=True, nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)
    points = db.Column(db.Integer(), default=0, nullable=False)
    first_name = db.Column(db.String(32), nullable=False, default='User')
    last_name = db.Column(db.String(32))
    is_confirmed = db.Column(db.Boolean(), default=False, nullable=False)
    is_admin = db.Column(db.Boolean(), default=False, nullable=False)

    def verify_password(self, password):
        return check_password(self.password, password)  # TODO: 2fa?

    def set_password(self, password):
        self.password = hash_password(password)

    def compose_message(self, subject, html_content, text_content):
        return Message(subject=subject,
                       recipients=[self.email],
                       body=text_content,
                       html=html_content)


class Task(db.Model, IDMixin):
    title = db.Column(db.String(), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User')
    category_id = db.Column(db.Integer(), db.ForeignKey('category.id'), nullable=False)
    category = db.relationship('Category')
    description = db.Column(db.String(), nullable=False)
    writeup = db.Column(db.String(), nullable=False)
    points = db.Column(db.Integer(), nullable=False)
    flag = db.Column(db.String(), nullable=False)
    is_proposal = db.Column(db.Boolean(), default=False, nullable=False)
    files = db.relationship('TaskFile')
    solved = db.relationship('User', secondary='solved_task')


class Category(db.Model, IDMixin):
    name = db.Column(db.String(), nullable=False, unique=True)
    tasks = db.relationship('Task')
    articles = db.relationship('Article')


class SolvedTask(db.Model, IDMixin):
    task_id = db.Column(db.Integer(), db.ForeignKey('task.id'), nullable=False)
    task = db.relationship('Task')
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')


class TaskFile(db.Model, IDMixin):
    task_id = db.Column(db.Integer(), db.ForeignKey('task.id'), nullable=False)
    task = db.relationship('Task')
    file = db.Column(db.String(), nullable=False)


class FlagSubmit(db.Model, IDMixin):
    flag = db.Column(db.String(), nullable=False)
    timestamp = db.Column(db.DateTime(), nullable=False)
    task_id = db.Column(db.Integer(), db.ForeignKey('task.id'), nullable=False)
    task = db.relationship('Task')
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')


class Article(db.Model, IDMixin):
    title = db.Column(db.String(), nullable=False)
    text = db.Column(db.String(), nullable=False)
    category = db.relationship('Category')
    category_id = db.Column(db.Integer(), db.ForeignKey('category.id'), nullable=False)
    comments = db.relationship('ArticleComment')


class ArticleComment(db.Model, IDMixin):
    comment = db.Column(db.String(), nullable=False)
    article_id = db.Column(db.Integer(), db.ForeignKey('article.id'), nullable=False)
    article = db.relationship('Article')
    author_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User')


class Captcha(db.Model, IDMixin):
    text = db.Column(db.String(), nullable=False, unique=True)
    timestamp = db.Column(db.DateTime(), nullable=False)


class EmailVerification(db.Model, IDMixin):
    code = db.Column(db.String(), nullable=False, unique=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')
    timestamp = db.Column(db.DateTime(), nullable=False)


class EmailRecovery(db.Model, IDMixin):
    code = db.Column(db.String(), nullable=False, unique=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')
    timestamp = db.Column(db.DateTime(), nullable=False)


db.create_all()
if User.query.get(1) is None:
    __u = User(id=1, **app.config.get('ADMIN_DATA'), is_confirmed=True, is_admin=True)
    __u.set_password(app.config.get('SITE_ADMIN_PASSWORD'))
    db.session.add(__u)
    del __u
db.session.commit()
