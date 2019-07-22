# YTCTF Platform API
# Copyright © 2019 Evgeniy Filimonov <evgfilim1@gmail.com>
# See full NOTICE at http://github.com/YummyTacos/YTCTF-API

from dataclasses import dataclass
from enum import Enum
from string import digits
from secrets import choice
from functools import wraps
from typing import Dict, Optional, List, NoReturn
from re import compile as compile_regex, IGNORECASE

from flask import request, g
from flask_restful import abort
from flask.views import MethodViewType
from itsdangerous import URLSafeTimedSerializer, BadSignature
from werkzeug.datastructures import MultiDict

from app import app
from data import models as db_models

__SECRET_KEY = app.config.get('SECRET_KEY')

token_serializer = URLSafeTimedSerializer(__SECRET_KEY, app.config.get('TOKEN_SALT'))
flag_re = compile_regex(app.config.get('FLAG_REGEXP', r'^\w+ctf\w+$'))
username_re = compile_regex(r'^[a-z0-9]+(?:[._][a-z0-9]+)*$', IGNORECASE)
email_re = compile_regex(r'^[a-z0-9\-_.+=]+@\w+(?:.\w+)*$', IGNORECASE)


def generate_code(length=6) -> str:
    return ''.join(choice(digits) for _ in range(length))


def current_user(token):
    if token is None:
        return
    try:
        t = token_serializer.loads(token, max_age=12 * 3600)  # 12 hours
    except BadSignature:
        return
    user_id = t.get('id')
    if user_id is None:
        return
    password = t.get('pw')
    if password is None:
        return
    user = db_models.User.query.get(user_id)
    if user is None:
        return
    if password != user.password:
        return
    return user


def get_data() -> MultiDict:
    data = MultiDict(request.args.deepcopy())
    if request.is_json:
        data.update(request.json)
    else:
        data.update(request.form)
    return data


def error(response_code: int, error_info: 'Errors', message=None, **kwargs) -> NoReturn:
    if message is None:
        message = error_info.value[1]
    abort(response_code, error_code=error_info.value[0], message=message, **kwargs)


def get_token():
    header = request.headers.get('Authorization', '').split(' ')
    if len(header) < 2 or header[0] != 'Bearer' or not header[1]:
        return None
    return header[1]


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if get_token() is None:
            return error(400, Errors.NO_TOKEN_PROVIDED, key='token')
        if g.api_user is None:
            return error(401, Errors.WRONG_OR_REVOKED_TOKEN)
        return f(*args, **kwargs)

    return wrapper


def confirmed_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if not g.api_user.is_confirmed:
            return error(403, Errors.NOT_CONFIRMED)
        return f(*args, **kwargs)

    return wrapper


class Errors(Enum):
    # request errors: 1x
    INTERNAL_ERROR = (10, 'Internal error')  # unused, but reserved
    NOT_ENOUGH_ARGS = (11, 'Not enough arguments were provided for this method')
    WRONG_ARG = (12, 'Wrong argument was provided')
    WRONG_TYPE = (13, 'Wrong argument type')
    NOT_FOUND = (14, 'Item not found')

    # login errors: 2x
    NO_TOKEN_PROVIDED = (20, 'No token was provided')
    WRONG_OR_REVOKED_TOKEN = (21, 'Wrong or revoked token was provided')
    CAPTCHA_REQUIRED = (22, 'Captcha required')
    CAPTCHA_INVALID = (23, 'Captcha is wrong, invalid or expired')

    # task errors: 3x
    FLAG_FORMAT_INVALID = (30, 'Flag format is invalid')
    WRONG_FLAG = (31, 'Wrong flag')
    TASK_ALREADY_SOLVED = (32, 'This task is already solved')
    CANNOT_SOLVE_TASK = (33, 'You cannot solve this task')

    # permission errors: 4x
    NOT_ADMIN = (40, 'You are not administrator')
    CANNOT_DELETE = (41, 'Cannot delete this')
    CANNOT_EDIT = (42, 'Cannot edit this')
    NOT_CONFIRMED = (43, 'You must confirm your account by confirming your email')
    ALREADY_CONFIRMED = (44, 'Your account is already confirmed')


@dataclass()
class Argument:
    name: str
    type: str
    description: str
    optional: Optional[bool] = None


class MethodDescription:
    TYPE_MAPPING = {
        str: 'String',
        int: 'Integer',
        bool: 'Boolean',
        bytes: 'Blob'
    }

    def __init__(self, method, info, *, auth=False, confirmed=False, admin=False):
        self.method: str = method
        self.info: Optional[str] = info
        self.auth_required: bool = auth
        self.admin_required: bool = admin
        self.confirmed_required: bool = confirmed
        self.args: List[Argument] = []
        self.returns: List[Argument] = []

    def _process_args(self, name, type_, description) -> Argument:
        if description is None:
            description = name.replace('_', ' ').capitalize()
        if isinstance(type_, type):
            type_ = self.TYPE_MAPPING.get(type_, type_.__name__)
        return Argument(name=name, type=type_, description=description)

    def add_param(self, name, type, description=None, optional=False):
        arg = self._process_args(name, type, description)
        arg.optional = optional
        self.args.append(arg)

    def add_return(self, name, type, description=None):
        arg = self._process_args(name, type, description)
        self.returns.append(arg)


class APIDocMeta(MethodViewType):
    # TODO: Auto check, auto pass (I think I need to override `flask_restful.Resource`)
    __DOC_TEMPLATE = """### `{endpoint}`
{description}
#### Methods:
{methods}"""  # TODO: header ids
    __METHOD_TEMPLATE = """##### {method_name}
{method_description}
###### Args:
{arg_list}
###### Returns:
{return_list}"""
    __ARG_LIST_TEMPLATE = '- `{name}` (`{type}`, _{requirement}_): {description}'
    __RETURN_LIST_TEMPLATE = '- `{name}` (`{type}`): {description}'

    def __init__(cls, name, bases, dict_):
        cls.__endpoint = None
        cls.__method_desc__: Dict[str, MethodDescription] = {}
        cls.__description__ = dict_.get('__doc__')
        cls.__doc_cache = None
        dict_['__doc__'] = None
        if '__endpoint__' in dict_:
            cls.__endpoint__ = dict_.pop('__endpoint__')
        if '__desc__' in dict_:
            descriptions = dict_.pop('__desc__')
            for description in descriptions:
                cls.__method_desc__[description.method] = description
        super().__init__(name, bases, dict_)

    @property
    def __endpoint__(cls):
        return cls.__endpoint or f'/{cls.__name__.lower()}'

    @__endpoint__.setter
    def __endpoint__(cls, value):
        if not isinstance(value, str):
            raise TypeError(f'value must be str, not {type(value).__name__}')
        if not value.startswith('/'):
            value = f'/{value}'
        cls.__endpoint = value

    @property
    def __doc__(cls):
        if cls.__doc_cache is not None:
            return cls.__doc_cache
        doc = cls.__DOC_TEMPLATE
        methods = []
        for method, args in cls.__method_desc__.items():
            method_t = cls.__METHOD_TEMPLATE
            arg_list = []
            return_list = []
            for arg in args.args:
                req = 'required' if not arg.optional else 'optional'
                arg_list.append(cls.__ARG_LIST_TEMPLATE.format(name=arg.name, type=arg.type,
                                                               description=arg.description,
                                                               requirement=req))
            for arg in args.returns:
                return_list.append(cls.__RETURN_LIST_TEMPLATE.format(name=arg.name, type=arg.type,
                                                                     description=arg.description))
            if len(arg_list) == 0:
                arg_list.append('- Nothing')
            if len(return_list) == 0:
                return_list.append('- Nothing')
            desc = args.info
            if args.admin_required:
                desc += ' _(requires admin rights)_'
            elif args.confirmed_required:
                desc += ' _(requires confirmed account)_'
            elif args.auth_required:
                desc += ' _(requires authentication)_'
            methods.append(method_t.format(method_name=method, method_description=desc,
                                           arg_list='\n'.join(arg_list),
                                           return_list='\n'.join(return_list)))
        cls.__doc_cache = doc.format(endpoint=cls.__endpoint__, description=cls.__description__,
                                     methods='\n'.join(methods))
        return cls.__doc__
