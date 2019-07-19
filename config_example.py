# YTCTF Platform API
# Copyright © 2019 Evgeniy Filimonov <evgfilim1@gmail.com>
# See full NOTICE at http://github.com/YummyTacos/YTCTF-API

from pathlib import Path

__version__ = '1.0.0'
REPOSITORY = 'https://github.com/YummyTacos/YTCTF-API'
CONTACT_URL = 'https://evgfilim1.me/'
CONTACT_NAME = 'Evgeniy Filimonov'

SECRET_KEY = b'secret key'
TOKEN_SALT = b'salt, which will be used to generate tokens'

cwd = Path(__file__).resolve().parent / 'data'
if not cwd.exists():
    cwd.mkdir(mode=0o755, parents=True)

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + str(cwd / 'app.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False

MAIL_USERNAME = 'mail@example.com'
MAIL_PASSWORD = 'MailPassword'
MAIL_DEFAULT_SENDER = '"Mail User" <mail@example.com>'
MAIL_SERVER = 'smtp.example.com'
MAIL_PORT = 465
MAIL_USE_SSL = True

ADMIN_DATA = dict(username='admin', email='admin@example.com', first_name='Admin')
SITE_ADMIN_PASSWORD = 'admin'
FLAG_REGEXP = r'^(test|yt)ctf[a-zA-Z0-9_]+$'
