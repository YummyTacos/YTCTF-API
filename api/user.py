# YTCTF Platform API
# Copyright © 2019 Evgeniy Filimonov <evgfilim1@gmail.com>
# See full NOTICE at http://github.com/YummyTacos/YTCTF-API

from datetime import datetime, timedelta
from io import BytesIO

from flask import request, g, Blueprint, url_for, send_file, current_app as app
from flask_restful import Resource

from data import models as db_models
from .helpers import (Errors, APIDocMeta, MethodDescription, token_serializer, current_user,
                      get_data, error, flag_re, username_re, email_re, login_required, get_token,
                      generate_code)
from . import models as api_models
from utils import find_user, get_captcha_img, render_email, send_mail, uptime

bp = Blueprint('user_api', __name__)

# TODO: error handler, events


@bp.before_request
def before_request():
    g.api_user = current_user(get_token())


class Auth(Resource, metaclass=APIDocMeta):
    """Use this method to authenticate in platform."""

    __endpoint__ = '/auth'

    __d_post = MethodDescription('POST', 'Authenticate')
    __d_post.add_param('username', str, 'Username for the user')
    __d_post.add_param('password', str, 'Password for the user')
    __d_post.add_return('token', str, 'Token which can be used to authenticate API requests')

    __desc__ = (__d_post,)

    @staticmethod
    def post():
        data = get_data()
        for key in ('username', 'password'):
            if key not in data:
                return error(400, Errors.NOT_ENOUGH_ARGS, f'{key} was not provided', key=key)
        user = find_user(data['username'])
        if user is None:
            return error(400, Errors.WRONG_ARG, 'Invalid username', key='username')
        if not user.verify_password(data['password']):
            return error(400, Errors.WRONG_ARG, 'Invalid password', key='password')
        return {
            'token': token_serializer.dumps({'id': user.id, 'pw': user.password})
        }


class Verify(Resource, metaclass=APIDocMeta):
    """Use this method to verify user's email"""

    __endpoint__ = '/verify'

    __d_post = MethodDescription('POST', 'Request email verification or verify email')
    __d_post.add_param('code', str, 'If provided, try to verify email, otherwise, request email'
                                    ' verification (requires authentication)', optional=True)
    __d_post.add_param('url', str, 'If provided, this URL will be used to provide alternative'
                                   ' verification method', optional=True)

    __desc__ = (__d_post,)

    @staticmethod
    @login_required
    def _request():
        if g.api_user.is_confirmed:
            error(400, Errors.ALREADY_CONFIRMED)
        code = generate_code()
        db_verification = db_models.EmailVerification(code=code, user_id=g.api_user.id,
                                                      timestamp=datetime.utcnow())
        link = get_data().get('url')
        html_text, plain_text = render_email('confirm', name=g.api_user.username, link=link,
                                             code=code)
        msg = g.api_user.compose_message('Регистрация', html_text, plain_text)
        db_models.db.session.add(db_verification)
        db_models.db.session.commit()
        send_mail(msg)
        return {}

    @classmethod
    def post(cls):
        code = get_data().get('code')
        if code is None:
            return cls._request()
        db_verification = db_models.EmailVerification.query.filter_by(code=code).one_or_none()
        if db_verification is None or \
                db_verification.timestamp + timedelta(hours=1) < datetime.utcnow():
            return error(400, Errors.WRONG_ARG, 'Invalid or expired code', key='code')
        db_verification.user.is_confirmed = True
        db_models.db.session.delete(db_verification)
        db_models.db.session.commit()
        return {}


class Recover(Resource, metaclass=APIDocMeta):
    """Use this method to recover account password"""

    __endpoint__ = '/recover'

    __d_post = MethodDescription('POST', 'Request password recovery email or confirm password'
                                         ' recovery')
    __d_post.add_param('code', str, 'If provided, try to recover account password, otherwise,'
                                    ' request password recovery email', optional=True)
    __d_post.add_param('email', str, 'Email of account to recover', optional=True)
    __d_post.add_param('url', str, 'If provided, this URL will be used to provide alternative'
                                   ' verification method', optional=True)
    __d_post.add_return('token', str, 'If account password recovery was requested and it succeeded,'
                                      ' token, which can be used to log in and change password,'
                                      ' empty string otherwise')

    __desc__ = (__d_post,)

    @staticmethod
    def _request():
        email = get_data().get('email')
        if email is None:
            error(400, Errors.NOT_ENOUGH_ARGS, 'Neither email nor code were provided', key='email')
        user = db_models.User.query.filter_by(email=email)
        if user is None:
            error(404, Errors.WRONG_ARG, 'user not found')
        if not user.is_confirmed:
            error(400, Errors.NOT_CONFIRMED, 'Cannot recover account as email was not confirmed')
        code = generate_code()
        db_recovery = db_models.EmailRecovery(code=code, user_id=user.id,
                                              timestamp=datetime.utcnow())
        link = get_data().get('url')
        html_text, plain_text = render_email('recover', name=user.username, link=link,
                                             code=code)
        msg = g.api_user.compose_message('Восстановление пароля', html_text, plain_text)
        db_models.db.session.add(db_recovery)
        db_models.db.session.commit()
        send_mail(msg)
        return {'token': ''}

    @classmethod
    def post(cls):
        code = get_data().get('code')
        if code is None:
            return cls._request()
        db_recovery = db_models.EmailRecovery.query.filter_by(code=code).one_or_none()
        if db_recovery is None or \
                db_recovery.timestamp + timedelta(hours=1) < datetime.utcnow():
            return error(400, Errors.WRONG_ARG, 'Invalid or expired code', key='code')
        user = db_recovery.user
        db_models.db.session.delete(db_recovery)
        db_models.db.session.commit()
        return {
            'token': token_serializer.dumps({'id': user.id, 'pw': user.password})
        }


class Register(Resource, metaclass=APIDocMeta):
    """Use this method to register in platform."""

    __endpoint__ = '/register'

    # FIXME: captcha doc
    __d_post = MethodDescription('POST', 'Register in platform. Send first request without captcha'
                                         '_id and captcha_data, then you will get captcha_id'
                                         ' together with a "Captcha required" error. Solve it and'
                                         ' send result as captcha_data back with captcha_id')
    __d_post.add_param('username', str, 'Username. Must contain only latin letters, digits,'
                                        ' underscores and dots')
    __d_post.add_param('first_name', str)
    __d_post.add_param('last_name', str, optional=True)
    __d_post.add_param('email', str, 'E-mail')
    __d_post.add_param('password', str)
    __d_post.add_param('captcha_id', str, 'ID of the captcha that can confirm your registration',
                       optional=True)
    __d_post.add_param('captcha_data', str, 'Solved captcha that can confirm your registration',
                       optional=True)
    __d_post.add_return('user_id', int, 'ID of successfully registered user')

    __desc__ = (__d_post,)

    @staticmethod
    def _collect_form():
        form_data = get_data()
        collected_form = {}
        for key in ('username', 'first_name', 'email', 'password'):
            if key not in form_data:
                return error(400, Errors.NOT_ENOUGH_ARGS, f'{key} was not provided', key=key)
            collected_form[key] = form_data[key]
        if 'last_name' in form_data:
            collected_form['last_name'] = form_data['last_name']
        return collected_form

    @staticmethod
    def _validate_data(form_data):
        username = form_data['username']
        first_name = form_data['first_name']
        last_name = form_data.get('last_name')
        email = form_data['email']
        password = form_data['password']
        if username_re.match(username) is None:
            return error(400, Errors.WRONG_ARG, 'Invalid username', key='username')
        if email_re.match(email) is None:
            return error(400, Errors.WRONG_ARG, 'Invalid email', key='email')
        u = db_models.User(username=username, email=email, first_name=first_name)
        if last_name is not None:
            u.last_name = last_name
        u.set_password(password)
        return u

    @staticmethod
    def _check_captcha():
        data = get_data()
        captcha_provided = 'captcha_id' in data
        if bool(captcha_provided ^ ('captcha_data' in data)):
            # either captcha_id or captcha_data was provided
            key = 'captcha_data' if captcha_provided else 'captcha_id'
            return error(400, Errors.NOT_ENOUGH_ARGS, 'Both captcha_id and captcha_data must be'
                                                      ' provided or missing', key=key)
        if not captcha_provided:
            code = generate_code()
            db_captcha = db_models.Captcha(text=code, timestamp=datetime.utcnow())
            db_models.db.session.add(db_captcha)
            db_models.db.session.commit()
            captcha_url = request.url_root.rstrip('/') + url_for('.get_captcha',
                                                                 captcha_id=db_captcha.id)
            return error(400, Errors.CAPTCHA_REQUIRED, captcha_id=db_captcha.id,
                         captcha_url=captcha_url)
        db_captcha = db_models.Captcha.query.get(data['captcha_id'])
        if db_captcha is None:
            return error(400, Errors.CAPTCHA_INVALID)
        expired = db_captcha.timestamp + timedelta(minutes=10) < datetime.utcnow()
        if expired or db_captcha.text != data['captcha_data']:
            db_models.db.session.delete(db_captcha)
            code = generate_code()
            db_captcha = db_models.Captcha(text=code, timestamp=datetime.utcnow())
            db_models.db.session.add(db_captcha)
            db_models.db.session.commit()
            captcha_url = request.url_root.rstrip('/') + url_for('.get_captcha',
                                                                 captcha_id=db_captcha.id)
            return error(400, Errors.CAPTCHA_INVALID, captcha_id=db_captcha.id,
                         captcha_url=captcha_url)
        db_models.db.session.delete(db_captcha)
        # will be committed after adding user

    @staticmethod
    def _check_credentials(username, email):
        esc = '|'
        username = username.replace('_', f'{esc}_')
        email = email.replace('_', f'{esc}_')
        t = db_models.User.query.filter(db_models.User.username.ilike(username, escape=esc)).all()
        if len(t) != 0:
            return error(400, Errors.WRONG_ARG, 'This username is registered', key='username')
        t = db_models.User.query.filter(db_models.User.email.ilike(email, escape=esc)).all()
        if len(t) != 0:
            return error(400, Errors.WRONG_ARG, 'This email is registered', key='email')

    @classmethod
    def post(cls):
        data = cls._collect_form()
        user = cls._validate_data(data)
        cls._check_credentials(data['username'], data['email'])
        cls._check_captcha()
        db_models.db.session.add(user)
        db_models.db.session.commit()
        return {'user_id': user.id}


class Tasks(Resource, metaclass=APIDocMeta):
    """Use this method to retrieve list of tasks"""

    __endpoint__ = '/tasks'

    __d_get = MethodDescription('GET', 'Get tasks')
    __d_get.add_return('tasks', 'List<Task>', 'Resulting list of tasks')

    __desc__ = (__d_get,)

    @staticmethod
    def get():
        tasks = db_models.Task.query
        if g.api_user is not None and not g.api_user.is_admin:
            tasks = tasks.filter(
                (db_models.Task.is_proposal.is_(True) &  # (proposal and you author) or not proposal
                 db_models.Task.author_id == g.api_user.id) |
                db_models.Task.is_proposal.isnot(True)
            )
        return {
            'tasks': [api_models.Task.from_db(task, full=True).to_dict() for task in tasks.all()]
        }


class Task(Resource, metaclass=APIDocMeta):
    """Use this method to retrieve task information or to send flags for the task."""

    __endpoint__ = '/task'

    __d_get = MethodDescription('GET', 'Get task')
    __d_get.add_param('id', int, 'Task ID')
    __d_get.add_return('task', 'Task')

    __d_post = MethodDescription('POST', 'Send task flag', auth=True)
    __d_post.add_param('id', int, 'Task ID')
    __d_post.add_param('flag', str, 'Task flag')

    __desc__ = (__d_get, __d_post)

    @staticmethod
    def _get_task():
        data = get_data()
        if 'id' not in data:
            return error(400, Errors.NOT_ENOUGH_ARGS, 'id was not provided', key='id')
        task = db_models.Task.query.get(int(data['id']))
        if task is None:
            return error(404, Errors.WRONG_ARG, 'No such task')
        if task.is_proposal and task.author_id != g.api_user.id:
            return error(403, Errors.NOT_ADMIN, 'You cannot view this task')
        return task

    @classmethod
    def get(cls):
        task = cls._get_task()
        task_api = api_models.Task.from_db(task, full=True)
        if g.api_user is not None and (g.api_user in task.solved or g.api_user.is_admin):
            task_api.writeup = task.writeup
        if g.api_user is not None and g.api_user.is_admin:
            task_api.flag = task.flag
        return {'task': task_api.to_dict()}

    @classmethod
    @login_required
    def post(cls):
        task = cls._get_task()
        data = get_data()
        if 'flag' not in data:
            return error(400, Errors.NOT_ENOUGH_ARGS, 'flag was not provided', key='flag')
        if g.api_user in task.solved:
            return error(403, Errors.TASK_ALREADY_SOLVED)
        if g.api_user.is_admin or g.api_user.id == task.author_id:
            error(403, Errors.CANNOT_SOLVE_TASK)
        flag = data['flag']
        m = flag_re.match(flag)
        if m is None:
            return error(400, Errors.FLAG_FORMAT_INVALID, key='flag')
        s = db_models.FlagSubmit(
            task_id=task.id,
            user_id=g.api_user.id,
            timestamp=datetime.utcnow(),
            flag=flag
        )
        db_models.db.session.add(s)
        if task.flag != flag:
            db_models.db.session.commit()
            return error(403, Errors.WRONG_FLAG)
        db_models.db.session.add(db_models.SolvedTask(task_id=task.id, user_id=g.api_user.id))
        g.api_user.points += task.points
        db_models.db.session.commit()
        return {}


class User(Resource, metaclass=APIDocMeta):
    """Use this method to retrieve information about the user"""

    __endpoint__ = '/user'

    __d_get = MethodDescription('GET', 'Get user info')
    __d_get.add_param('id', int, 'User ID. If not provided, returns info about current user',
                      optional=True)
    __d_get.add_return('user', 'User')

    __d_patch = MethodDescription('PATCH', 'Edit current user info', auth=True)
    __d_patch.add_param('id', int, 'User ID to edit (requires admin rights)', optional=True)
    __d_patch.add_param('username', str, 'New username', optional=True)
    __d_patch.add_param('email', str, 'New email. Resets confirmation status, if present',
                        optional=True)
    __d_patch.add_param('first_name', str, 'New first name', optional=True)
    __d_patch.add_param('last_name', str, 'New last name', optional=True)
    __d_patch.add_param('password', str, 'New password', optional=True)
    __d_patch.add_param('is_admin', int, 'If this is set to 0, removes admin rights, else if this'
                                         ' is set to 1, sets admin rights (requires admin rights)',
                        optional=True)

    __desc__ = (__d_get, __d_patch)  # TODO: `DELETE /user`

    @staticmethod
    def _get_user():
        user_id = get_data().get('id', type=int)
        if user_id is None:
            if g.api_user is None:
                return error(400, Errors.NOT_ENOUGH_ARGS, 'neither id nor token were not provided',
                             key='id')
            user_id = g.api_user.id
        user = db_models.User.query.get(user_id)
        if user is None:
            return error(404, Errors.WRONG_ARG, 'User was not found')
        return user

    @classmethod
    def _validate(cls, key, value):
        allowed_args = [arg.name for arg in cls.__method_desc__['PATCH'].args]
        if key not in allowed_args:
            return False  # skip validation
        if key == 'username':
            if username_re.match(value) is None:
                error(400, Errors.WRONG_ARG, 'username is invalid', key=key)
        if key == 'email':
            if email_re.match(value) is None:
                error(400, Errors.WRONG_ARG, 'email is invalid', key=key)
        if key == 'first_name':
            if not value:
                error(400, Errors.WRONG_ARG, 'first_name is invalid', key=key)
        if key == 'password':
            if not value:
                error(400, Errors.WRONG_ARG, 'password is invalid', key=key)
        if key == 'is_admin':
            if value not in ('0', '1'):
                error(400, Errors.WRONG_ARG, 'is_admin must be either 0 or 1', key=key)
        return True

    @classmethod
    def get(cls):
        user = cls._get_user()
        api_user = api_models.User.from_db(user, full=True)
        if g.api_user is not None and (g.api_user.is_admin or user.id == g.api_user.id):
            api_user.email = user.email
        return {'user': api_user.to_dict()}

    @classmethod
    @login_required
    def patch(cls):
        data = get_data()
        if 'id' in data:
            value = int(data['id'])
            if not g.api_user.is_admin and g.api_user.id != value:
                error(403, Errors.NOT_ADMIN)
            user = db_models.User.query.get(value)
            if user is None:
                error(404, Errors.WRONG_ARG, 'User not found')
        else:
            user = g.api_user
        for key, value in data.items():
            if not cls._validate(key, value):
                continue
            if key == 'last_name':
                if not value:
                    value = None
            if key == 'is_admin':
                if not g.api_user.is_admin:
                    error(403, Errors.NOT_ADMIN)
                value = bool(int(value))
            if key == 'email':
                user.is_confirmed = False
            if key != 'password':
                setattr(user, key, value)
            else:
                user.set_password(value)
        db_models.db.session.commit()
        api_user = api_models.User.from_db(user, full=True)
        if g.api_user is not None and (g.api_user.is_admin or user.id == g.api_user.id):
            api_user.email = user.email
        return {
            'task': api_user.to_dict()
        }


class Users(Resource, metaclass=APIDocMeta):
    """Use this method to retrieve all users."""

    __endpoint__ = '/users'

    __d_get = MethodDescription('GET', 'Get users')
    __d_get.add_return('users', 'List<User>', 'Resulting list of users')

    __desc__ = (__d_get,)

    @staticmethod
    def get():
        return {
            'users': [
                api_models.User.from_db(user, full=True).to_dict()
                for user in db_models.User.query.all()
            ]
        }


class Category(Resource, metaclass=APIDocMeta):
    """Use this method to retrieve category information"""

    __endpoint__ = '/category'

    __d_get = MethodDescription('GET', 'Get category')
    __d_get.add_param('id', int, 'Category ID')
    __d_get.add_return('category', 'Category')

    __desc__ = (__d_get,)

    @staticmethod
    def get():
        data = get_data()
        if 'id' not in data:
            return error(400, Errors.NOT_ENOUGH_ARGS, 'id was not provided', key='id')
        category = db_models.Category.query.get(int(data['id']))
        if category is None:
            return error(404, Errors.WRONG_ARG, 'No such category')
        category_api = api_models.Category.from_db(category, full=True)
        return {'category': category_api.to_dict()}


class Categories(Resource, metaclass=APIDocMeta):
    """Use this method to retrieve all categories"""

    __endpoint__ = '/categories'

    __d_get = MethodDescription('GET', 'Get categories')
    __d_get.add_return('categories', 'List<Category>', 'Resulting list of categories')

    __desc__ = (__d_get,)

    @staticmethod
    def get():
        return {
            'categories': [
                api_models.Category.from_db(category, full=True).to_dict()
                for category in db_models.Category.query.all()
            ]
        }


class Article(Resource, metaclass=APIDocMeta):
    """Use this method to retrieve article"""

    __endpoint__ = '/article'

    __d_get = MethodDescription('GET', 'Get article')
    __d_get.add_param('id', int, 'Article ID')
    __d_get.add_return('article', 'Article')

    __desc__ = (__d_get,)

    @staticmethod
    def get():
        data = get_data()
        if 'id' not in data:
            return error(400, Errors.NOT_ENOUGH_ARGS, 'id was not provided', key='id')
        article = db_models.Article.query.get(int(data['id']))
        if article is None:
            return error(404, Errors.WRONG_ARG, 'No such article')
        article_api = api_models.Article.from_db(article, full=True)
        return {'article': article_api.to_dict()}


class Articles(Resource, metaclass=APIDocMeta):
    """Use this method to retrieve articles"""

    __endpoint__ = '/articles'

    __d_get = MethodDescription('GET', 'Get articles')
    __d_get.add_param('category_id', int, 'If provided, filter articles by category, otherwise'
                                          ' return all articles', optional=True)
    __d_get.add_return('articles', 'List<Article>', 'Resulting list of articles')

    __desc__ = (__d_get,)

    @staticmethod
    def get():
        query = db_models.Article.query
        category_id = get_data().get('category_id')
        if category_id is not None:
            category = db_models.Category.query.get(category_id)
            if category is None:
                error(404, Errors.WRONG_ARG, 'category not found')
            query = query.filter_by(category_id=category.id)
        return {
            'articles': [
                api_models.Article.from_db(article, full=True).to_dict()
                for article in query.all()
            ]
        }


class About(Resource, metaclass=APIDocMeta):
    """Use this method to get information about this platform"""

    __endpoint__ = '/about'

    __d_get = MethodDescription('GET', 'About platform')
    __d_get.add_return('name', str, 'Platform name')
    __d_get.add_return('version', str, 'Platform version')
    __d_get.add_return('license', str, 'Platform distribution license')
    __d_get.add_return('license_url', str, 'Platform distribution license URL')
    __d_get.add_return('repository', str, 'Platform repository URL')
    __d_get.add_return('contact', str, 'Contact name in case of questions')
    __d_get.add_return('contact_url', str, 'Contact URL in case of questions')
    __d_get.add_return('uptime', int, 'Platform uptime (seconds)')

    __desc__ = (__d_get,)

    @staticmethod
    def get():
        return {
            'name': 'ytctf-platform-api',
            'version': app.config.get('__version__', '1.0.0'),
            'license': 'AGPL-3.0-or-later',
            'license_url': 'https://spdx.org/licenses/AGPL-3.0-or-later.html',
            'uptime': int((datetime.utcnow() - uptime).total_seconds()),
            'repository': app.config.get('REPOSITORY'),
            'contact_url': app.config.get('CONTACT_URL'),
            'contact': app.config.get('CONTACT_NAME')
        }


@bp.route('/captcha/<int:captcha_id>')
def get_captcha(captcha_id):
    db_captcha = db_models.Captcha.query.get(captcha_id)
    if db_captcha is None or db_captcha.timestamp + timedelta(minutes=10) < datetime.utcnow():
        return 'Invalid captcha_id', 400
    im = get_captcha_img(db_captcha.text)
    b = BytesIO()
    im.save(b, format='PNG')
    b.seek(0)
    return send_file(b, mimetype='image/png')
