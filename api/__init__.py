# YTCTF Platform API
# Copyright © 2019 Evgeniy Filimonov <evgfilim1@gmail.com>
# See full NOTICE at http://github.com/YummyTacos/YTCTF-API

from typing import Iterable

from . import user, admin, helpers, models
from flask import request
from flask_restful import Resource


class APIDoc(Resource, metaclass=helpers.APIDocMeta):
    """Use this method to retrieve API documentation"""

    __endpoint__ = '/docs'

    __d_get = helpers.MethodDescription('GET', 'Get API documentation')
    __d_get.add_param('method', str, 'If provided, return documentation for this method, otherwise'
                                     ' return documentation for all methods', optional=True)
    __d_get.add_return('doc', 'Mapping<str, str>', 'Documentation in Markdown format. "_" key is'
                                                   ' documentation header, which describes how to'
                                                   ' make requests')

    __desc__ = (__d_get,)

    @staticmethod
    def get():
        # TODO: do not render documentation server-side, use custom objects to describe
        doc = {}
        method = helpers.get_data().get('method')
        for resource in iter_resources():
            if method is not None and resource.__endpoint__ != method:
                continue
            doc[resource.__endpoint__] = resource.__doc__
        doc['_'] = """## Making requests
All queries to the API need to be presented in this form: \
`{base}/METHOD_NAME`. Like this for example: \
`{base}/tasks`

API supports four ways of passing parameters in requests:
- URL query string
- `application/x-www-form-urlencoded`
- `application/json` (except for uploading files)
- `multipart/form-data` (use to upload files)

The response contains a JSON object. On success, an object in Endpoints section is returned. \
Otherwise, object with `error_code` and human-readable `message` is returned. \
Some errors may also have an optional String field `key`, which can help to handle the error.

## Authentication
To use methods, which require authentication, confirmed account or admin rights, you must provide \
token as `Authorization` HTTP header like this: `Authorization: Bearer <token>`, where `<token>` \
is your token (you can get it by authenticating, see Endpoints section for more).

## Endpoints""".format(base=request.url_root.rstrip('/'))
        return {'doc': doc}


def iter_resources(modules=None):
    if modules is None:
        modules = (user, admin)
    elif not isinstance(modules, Iterable):
        modules = (modules,)
    for module in modules:
        for cls_name in dir(module):
            cls = getattr(module, cls_name)
            if not isinstance(cls, helpers.APIDocMeta) or cls is helpers.APIDocMeta:
                continue
            yield cls
        if module is user:
            yield APIDoc
