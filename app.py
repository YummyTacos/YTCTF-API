# YTCTF Platform API
# Copyright © 2019 Evgeniy Filimonov <evgfilim1@gmail.com>
# See full NOTICE at http://github.com/YummyTacos/YTCTF-API

from flask import Flask
from flask_cors import CORS
from flask_mail import Mail

app = Flask(__name__)
app.config.from_object('config')
Mail(app)
CORS(app)
