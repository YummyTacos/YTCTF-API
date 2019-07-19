# YTCTF Platform API
# Copyright © 2019 Evgeniy Filimonov <evgfilim1@gmail.com>
# See full NOTICE at http://github.com/YummyTacos/YTCTF-API

from app import app
from flask_restful import Api

import api

app_api = Api(api.user.bp)
app_admin_api = Api(api.admin.bp)

for resource in api.iter_resources(api.user):
    app_api.add_resource(resource, resource.__endpoint__)
for resource in api.iter_resources(api.admin):
    app_admin_api.add_resource(resource, resource.__endpoint__)

app.register_blueprint(api.user.bp)
app.register_blueprint(api.admin.bp)

if __name__ == '__main__':
    app.run()
