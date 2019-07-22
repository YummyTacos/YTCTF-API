# YTCTF Platform API
# Copyright © 2019 Evgeniy Filimonov <evgfilim1@gmail.com>
# See full NOTICE at http://github.com/YummyTacos/YTCTF-API

import os
from functools import wraps
from pathlib import Path

from flask import Blueprint, g, request
from flask_restful import Resource
from werkzeug.utils import secure_filename

from data import models as db_models
from . import models as api_models
from .helpers import (current_user, get_data, Errors, APIDocMeta, MethodDescription, error,
                      login_required, flag_re, confirmed_required, get_token)

bp = Blueprint('admin_api', __name__)


@bp.before_request
def before_request():
    g.api_user = current_user(get_token())


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if not g.api_user.is_admin:
            error(403, Errors.NOT_ADMIN)
        return f(*args, **kwargs)

    return wrapper


class Task(Resource, metaclass=APIDocMeta):
    """Use this method to manage tasks."""

    __endpoint__ = '/admin/task'

    __d_patch = MethodDescription('PATCH', 'Edit task (if user is admin, this also confirms task'
                                           ' proposal)', confirmed=True)
    __d_patch.add_param('id', int, 'Task ID to edit')
    __d_patch.add_param('title', str, 'New task name', optional=True)
    __d_patch.add_param('author', int, 'User ID of new task author', optional=True)
    __d_patch.add_param('category', str, 'New task category', optional=True)
    __d_patch.add_param('points', int, 'New task points, must be positive', optional=True)
    __d_patch.add_param('description', str, 'New task description', optional=True),
    __d_patch.add_param('writeup', str, 'New task write-up (solution)', optional=True)
    __d_patch.add_param('flag', str, 'New task flag', optional=True)
    __d_patch.add_return('task', 'Task', 'Edited task')

    __d_post = MethodDescription('POST', 'Create or propose new task', confirmed=True)
    __d_post.add_param('title', str, 'Task name')
    __d_post.add_param('author', int, 'If provided, user ID of task author (cannot be set on task'
                                      ' proposals), otherwise current user ID',
                       optional=False)
    __d_post.add_param('category', str, 'Task category')
    __d_post.add_param('points', int, 'Task points, must be positive')
    __d_post.add_param('description', str, 'Task description'),
    __d_post.add_param('writeup', str, 'Task write-up (solution)')
    __d_post.add_param('flag', str, 'Task flag')
    __d_post.add_return('task', 'Task', 'Created task')

    __d_delete = MethodDescription('DELETE', 'Delete task', confirmed=True)
    __d_delete.add_param('id', int, 'Task ID to delete')

    __desc__ = (__d_post, __d_patch, __d_delete)

    @staticmethod
    def _get_task():
        data = get_data()
        if 'id' not in data:
            return error(400, Errors.NOT_ENOUGH_ARGS, 'id was not provided', key='id')
        task = db_models.Task.query.get(int(data['id']))
        if task is None:
            error(400, Errors.NOT_FOUND, 'No such task', key='id')
        return task

    @classmethod
    def _validate(cls, key, value):
        allowed_args = [arg.name for arg in cls.__method_desc__['POST'].args]
        if key not in allowed_args:
            return False  # skip validation
        if key == 'title':
            if '\n' in value:
                error(400, Errors.WRONG_ARG, 'Task name must not contain newline separators',
                      key=key)
        if key == 'author':
            if db_models.User.query.get(int(value)) is None:
                error(400, Errors.WRONG_ARG, 'Author not found', key=key)
        if key == 'category':
            if db_models.Category.query.get(int(value)) is None:
                error(400, Errors.WRONG_ARG, 'Category not found', key=key)
        if key == 'points':
            if isinstance(value, str) and not value.isdecimal():
                error(400, Errors.WRONG_TYPE, 'Points value is not decimal number', key=key)
            value = int(value)
            if value < 0:
                error(400, Errors.WRONG_ARG, 'Points value is negative', key=key)
            if value % 25 != 0:
                error(400, Errors.WRONG_ARG, 'Points value is not multiple of 25', key=key)
        if key in ('description', 'writeup', 'title'):
            if not value:
                error(400, Errors.WRONG_ARG, f'{key} cannot be empty', key=key)
        if key == 'flag':
            if flag_re.match(value) is None:
                error(400, Errors.FLAG_FORMAT_INVALID, key=key)
        return True

    @classmethod
    @confirmed_required
    def post(cls):
        task = db_models.Task()
        data = get_data()
        allowed_args = [arg.name for arg in cls.__method_desc__['POST'].args]
        if not g.api_user.is_admin and 'author' in data:
            error(400, Errors.WRONG_ARG, 'Setting task author is prohibited on task proposals',
                  key='author')
        elif 'author' not in data:
            data['author'] = g.api_user.id
        for arg in allowed_args:
            if arg not in data:
                error(400, Errors.NOT_ENOUGH_ARGS, f'{arg} was not provided', key=arg)
        for key, value in data.items():
            if not cls._validate(key, value):
                continue
            if key == 'points':
                value = int(value)
            if key == 'author':
                key = 'author_id'
                value = int(value)
            if key == 'category':
                key = 'category_id'
                value = int(value)
            setattr(task, key, value)
        if not g.api_user.is_admin:
            task.is_proposal = True
        else:
            task.is_proposal = False
            db_models.User.query.get(task.author_id).points += task.points
        db_models.db.session.add(task)
        db_models.db.session.commit()
        return {
            'task': api_models.Task.from_db(task, full=True).to_dict()
        }

    @classmethod
    @confirmed_required
    def patch(cls):
        task = cls._get_task()
        data = get_data()
        if not g.api_user.is_admin and not (task.is_proposal and task.author_id == g.api_user.id):
            error(403, Errors.NOT_ADMIN)
        diff = 0
        for key, value in data.items():
            if not cls._validate(key, value):
                continue
            if key == 'points':
                value = int(value)
                diff = task.points - value
            if key == 'author':
                key = 'author_id'
                value = int(value)
            if key == 'category':
                key = 'category_id'
                value = int(value)
            setattr(task, key, value)
        if diff != 0:
            for s in db_models.SolvedTask.query.filter_by(task_id=task.id).all():
                s.user.points -= diff
        if g.api_user.is_admin:
            task.is_proposal = False
        db_models.db.session.commit()
        return {
            'task': api_models.Task.from_db(task, full=True).to_dict()
        }

    @classmethod
    @confirmed_required
    def delete(cls):
        task = cls._get_task()
        if not (task.is_proposal and task.author_id == g.api_user.id):
            error(403, Errors.NOT_ADMIN)
        for s in db_models.SolvedTask.query.filter_by(task_id=task.id).all():
            s.user.points -= task.points
            db_models.db.session.delete(s)
        for file in task.files:
            os.remove((Path(bp.static_folder) / f'files/tasks/{task.id}/{file.file}').resolve())
            db_models.db.session.delete(file)
        for s in db_models.FlagSubmit.query.filter_by(task_id=task.id).all():
            db_models.db.session.delete(s)
        db_models.db.session.delete(task)
        db_models.db.session.commit()
        return {}


class TaskFile(Resource, metaclass=APIDocMeta):
    """Use this method to manage task files"""

    __endpoint__ = '/admin/file'

    __d_post = MethodDescription('POST', 'Send file and attach it to task', confirmed=True)
    __d_post.add_param('task_id', int, 'Task ID')
    __d_post.add_param('file', 'multipart/form-data')
    __d_post.add_return('file', 'File', 'Added file')

    __d_delete = MethodDescription('DELETE', 'Delete file', confirmed=True)
    __d_delete.add_param('id', int, 'File ID to delete')

    __desc__ = (__d_post, __d_delete)

    @staticmethod
    @confirmed_required
    def post():
        task_id = get_data().get('task_id')
        if task_id is None:
            error(400, Errors.NOT_ENOUGH_ARGS, 'task_id was not provided', key='task_id')
        task = db_models.Task.query.get(task_id)
        if task is None:
            error(400, Errors.NOT_FOUND, 'No such task', key='task_id')
        if not g.api_user.is_admin and (not task.is_proposal or task.author_id != g.api_user.id):
            error(403, Errors.NOT_ADMIN)
        file = request.files.get('file')
        if file is None:
            error(400, Errors.NOT_ENOUGH_ARGS, 'file was not provided', key='file')
        filename = secure_filename(file.filename)
        base_dir = (Path(bp.static_folder) / f'files/tasks/{task.id}').resolve()
        base_dir.mkdir(parents=True, exist_ok=True)
        file.save(str(base_dir / filename))
        db_file = db_models.TaskFile(file=filename)
        db_models.db.session.add(db_file)
        task.files.append(db_file)
        db_models.db.session.commit()
        return {
            'file': api_models.File.from_db(db_file, full=True).to_dict()
        }

    @staticmethod
    @confirmed_required
    def delete():
        file_id = get_data().get('id')
        if file_id is None:
            error(400, Errors.NOT_ENOUGH_ARGS, 'id was not provided', key='id')
        file = db_models.TaskFile.query.get(file_id)
        if file is None:
            error(400, Errors.NOT_FOUND, 'File not found', key='id')
        task = file.task
        if not g.api_user.is_admin and (not task.is_proposal or task.author_id != g.api_user.id):
            error(403, Errors.NOT_ADMIN)
        os.remove((Path(bp.static_folder) / f'files/tasks/{task.id}/{file.file}').resolve())
        db_models.db.session.delete(file)
        db_models.db.session.commit()
        return {}


class Category(Resource, metaclass=APIDocMeta):
    """Use this method to manage categories"""

    __endpoint__ = '/admin/category'

    __d_patch = MethodDescription('PATCH', 'Edit category', admin=True)
    __d_patch.add_param('id', int, 'Category ID')
    __d_patch.add_param('name', str, 'New category name', optional=True)
    __d_patch.add_return('category', 'Category', 'Edited category')

    __d_post = MethodDescription('POST', 'Create new category', admin=True)
    __d_post.add_param('name', str, 'Category name')
    __d_post.add_return('category', 'Category', 'Created category')

    __d_delete = MethodDescription('DELETE', 'Delete category', admin=True)
    __d_delete.add_param('id', int, 'Category ID')

    __desc__ = (__d_post, __d_patch, __d_delete)

    @staticmethod
    def _get_category():
        category_id = get_data().get('id')
        if category_id is None:
            error(400, Errors.NOT_ENOUGH_ARGS, 'id was not provided', key='id')
        category = db_models.Category.query.get(category_id)
        if category is None:
            error(400, Errors.NOT_FOUND, 'Category not found', key='id')
        return category

    @staticmethod
    @admin_required
    def post():
        category_name = get_data().get('name')
        if not category_name:
            error(400, Errors.NOT_ENOUGH_ARGS, 'name was not provided', key='name')
        exists = db_models.Category.query.filter_by(name=category_name).one_or_none() is not None
        if exists:
            error(400, Errors.WRONG_ARG, 'This category already exists', key='name')
        category = db_models.Category(name=category_name)
        db_models.db.session.add(category)
        db_models.db.session.commit()
        return {
            'category': api_models.Category.from_db(category, full=True).to_dict()
        }

    @classmethod
    @admin_required
    def patch(cls):
        category = cls._get_category()
        category_name = get_data().get('name')
        if category_name:
            if db_models.Category.query.filter_by(name=category_name).one_or_none() is not None:
                error(400, Errors.WRONG_ARG, 'This category already exists', key='name')
            category.name = category_name
        db_models.db.session.commit()
        return {
            'category': api_models.Category.from_db(category, full=True).to_dict()
        }

    @classmethod
    @admin_required
    def delete(cls):
        category = cls._get_category()
        for task in category.tasks:
            # Find first conflict
            error(400, Errors.CANNOT_DELETE, f'Cannot delete category as it is used by'
                                             f' task_id={task.id}', key='id')
        for article in category.articles:
            # Find first conflict
            error(400, Errors.CANNOT_DELETE, f'Cannot delete category as it is used by'
                                             f' article_id={article.id}', key='id')
        db_models.db.session.delete(category)
        db_models.db.session.commit()
        return {}


class Article(Resource, metaclass=APIDocMeta):
    """Use this method to manage articles"""

    __endpoint__ = '/admin/article'

    __d_patch = MethodDescription('PATCH', 'Edit article', admin=True)
    __d_patch.add_param('id', int, 'Article ID')
    __d_patch.add_param('title', str, 'New article title', optional=True)
    __d_patch.add_param('text', str, 'New article text', optional=True)
    __d_patch.add_param('category', int, 'New category ID for article', optional=True)
    __d_patch.add_return('article', 'Article', 'Edited article')

    __d_post = MethodDescription('POST', 'Create new article', admin=True)
    __d_post.add_param('title', str, 'Article title')
    __d_post.add_param('text', str, 'Article text')
    __d_post.add_param('category', int, 'Category ID for article')
    __d_post.add_return('article', 'Article', 'Created article')

    __d_delete = MethodDescription('DELETE', 'Delete article', admin=True)
    __d_delete.add_param('id', int, 'Article ID')

    __desc__ = (__d_post, __d_patch, __d_delete)

    @staticmethod
    def _get_article():
        data = get_data()
        if 'id' not in data:
            return error(400, Errors.NOT_ENOUGH_ARGS, 'id was not provided', key='id')
        article = db_models.Article.query.get(data['id'])
        if article is None:
            error(400, Errors.NOT_FOUND, 'No such article', key='id')
        return article

    @classmethod
    def _validate(cls, key, value):
        allowed_args = [arg.name for arg in cls.__method_desc__['POST'].args]
        if key not in allowed_args:
            return False  # skip validation
        if key == 'title':
            if '\n' in value:
                error(400, Errors.WRONG_ARG, 'Article title must not contain newline separators',
                      key=key)
        if key == 'title' or key == 'text':
            if not value:
                error(400, Errors.WRONG_ARG, f'{key} cannot be empty', key=key)
        if key == 'category':
            if db_models.Category.query.get(int(value)) is None:
                error(400, Errors.WRONG_ARG, 'Category not found', key=key)
        return True

    @classmethod
    @admin_required
    def post(cls):
        article = db_models.Article()
        data = get_data()
        allowed_args = [arg.name for arg in cls.__method_desc__['POST'].args]
        for arg in allowed_args:
            if arg not in data:
                error(400, Errors.NOT_ENOUGH_ARGS, f'{arg} was not provided', key=arg)
        for key, value in data.items():
            if not cls._validate(key, value):
                continue
            if key == 'category':
                key = 'category_id'
                value = int(value)
            setattr(article, key, value)
        db_models.db.session.add(article)
        db_models.db.session.commit()
        return {
            'article': api_models.Article.from_db(article, full=True).to_dict()
        }

    @classmethod
    @admin_required
    def patch(cls):
        article = cls._get_article()
        data = get_data()
        for key, value in data.items():
            if not cls._validate(key, value):
                continue
            if key == 'category':
                key = 'category_id'
                value = int(value)
            setattr(article, key, value)
        db_models.db.session.commit()
        return {
            'article': api_models.Article.from_db(article, full=True).to_dict()
        }

    @classmethod
    @admin_required
    def delete(cls):
        article = cls._get_article()
        db_models.db.session.delete(article)
        db_models.db.session.commit()
        return {}
