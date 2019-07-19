# YTCTF Platform API
# Copyright © 2019 Evgeniy Filimonov <evgfilim1@gmail.com>
# See full NOTICE at http://github.com/YummyTacos/YTCTF-API

from datetime import datetime
from re import compile as re_compile
from threading import Thread

from flask import g, request, current_app as app, render_template
from bcrypt import gensalt, hashpw, checkpw
from captcha.image import ImageCaptcha, Image

_safe_url_re = re_compile(r'^/[^/].*')  # Prevent cross-site redirects (proto:// and // fails)
_captcha_generator = ImageCaptcha()
uptime = datetime.utcnow()


def render_email(template, **kwargs):
    # noinspection PyUnresolvedReferences
    return (render_template(f'{template}_email.html', **kwargs),
            render_template(f'{template}_email.txt', **kwargs))


def send_mail(msg):
    t = Thread(target=app.extensions['mail'].send, args=(msg,))
    t.start()
    return t


def find_user(name):
    from data.models import User
    return User.query.filter_by(username=name).one_or_none()


def check_password(hashed_pw, pw):
    if not isinstance(hashed_pw, bytes):
        hashed_pw = hashed_pw.encode('UTF-8')
    if not isinstance(pw, bytes):
        pw = pw.encode('UTF-8')
    return checkpw(pw, hashed_pw)


def hash_password(pw):
    if not isinstance(pw, bytes):
        pw = pw.encode('UTF-8')
    return hashpw(pw, gensalt()).decode()


def get_captcha_img(chars) -> Image.Image:
    img = _captcha_generator.generate_image(chars)
    return img
