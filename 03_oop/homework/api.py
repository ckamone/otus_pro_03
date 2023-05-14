"""Web server"""
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import hashlib
import json
import logging
import re
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from optparse import OptionParser

import scoring

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class TypedProperty:
    """Base class"""
    nullable_list = [0, '', {}, []]

    def __init__(self, name='default', default=None, type=str, required=False, nullable=True):
        self.required = required
        self.nullable = nullable
        self.name = "_" + name
        self.type = type
        self.default = default if default else type()

    def __get__(self, instance, cls):
        return getattr(instance, self.name, self.default)

    def validate(func):
        """Base validation"""
        def _wrapper(self, instance, value):
            if self.required and value is None:
                raise TypeError(f"value is required, but you give {repr(value)}")

            if not self.nullable and value in self.nullable_list:
                raise TypeError(f"nullable is {self.nullable}, but you give {repr(value)}")

            func(self, instance, value)

        return _wrapper

    @validate
    def __set__(self, instance, value):
        if not isinstance(value, self.type):
            raise TypeError(f"Must be a {self.type}")
        setattr(instance, self.name, value)


class CharField(TypedProperty):
    """Char type"""
    def __init__(self, name='default', type=str, required=False, nullable=True):
        super().__init__(name=name, type=type, required=required, nullable=nullable)


class IntegerField(TypedProperty):
    """Integer type"""
    def __init__(self, name='default', type=int, required=False, nullable=True):
        super().__init__(name=name, type=type, required=required, nullable=nullable)


class EmailField(CharField):
    """EmailField"""
    def __set__(self, instance, value):
        if not isinstance(value, self.type):
            raise TypeError(f"Must be a {self.type}")
        check_format = re.findall(r'\w+@\w+.\w+', value)
        check_at_symbol_count = re.findall(r'@\w+@', value)
        if any((
                not check_format,
                check_at_symbol_count,
        )):
            raise TypeError("Bad email")
        setattr(instance, self.name, value)


class ArgumentsField(TypedProperty):
    """ArgumentsField"""
    def __init__(self, name='default', type=dict, required=False, nullable=True):
        super().__init__(name=name, type=type, required=required, nullable=nullable)


class PhoneField(IntegerField):
    """PhoneField"""
    def validate_phone(func):
        """phone validation"""
        def _wrapper(*args):
            try:
                value = int(args[2])
                result = re.findall(r'7\d+', str(value))
                if not result or len(result[0]) != 11:
                    raise TypeError("Bad phone format")
                func(*args)
            except Exception:
                raise TypeError("Bad phone type")
        return _wrapper

    @validate_phone
    def __set__(self, instance, value):
        setattr(instance, self.name, value)


class DateField(TypedProperty):
    """DateField"""
    def __init__(self, name='default',
                 default=datetime.datetime(2000, 1, 1),
                 type=datetime.datetime,
                 required=False,
                 nullable=True):
        super().__init__(name=name, default=default,
                         type=type, required=required, nullable=nullable)

    def validate_datefield(func):
        """datefield validation"""
        def _wrapper(self, instance, value):
            try:
                value = datetime.datetime.strptime(value, '%d.%m.%Y')
                func(self, instance, value)
            except Exception:
                raise TypeError("Wrong date format")

        return _wrapper

    @validate_datefield
    def __set__(self, instance, value):
        setattr(instance, self.name, value)


class BirthDayField(DateField):
    """BirthDayField"""
    def validate_bday(func):
        """bday validation"""
        def _wrapper(self, instance, value):
            try:
                value = datetime.datetime.strptime(value, '%d.%m.%Y')
                if value.year < 1920:
                    raise TypeError("Year cant be smaller than 1920")
                if value.year > datetime.datetime.now().year - 18:
                    raise TypeError("18+ only")
                func(self, instance, value)
            except Exception:
                raise TypeError("Wrong date format")

        return _wrapper

    @validate_bday
    def __set__(self, instance, value):
        setattr(instance, self.name, value)


class GenderField(IntegerField):
    """GenderField"""
    def validate_gender(func):
        """validate gender"""
        def _wrapper(self, instance, value):
            if not isinstance(value, self.type):
                raise TypeError(f"Must be a {self.type}")
            if value < 0 or value > 2:
                raise TypeError("Bad gender type")
            func(self, instance, value)

        return _wrapper

    @validate_gender
    def __set__(self, instance, value):
        setattr(instance, self.name, value)


class ClientIDsField(TypedProperty):
    """ClientIDsField"""
    def __init__(self, name='default', type=list, required=False, nullable=True):
        super().__init__(name=name, type=type, required=required, nullable=nullable)

    def validate_ids_list(func):
        """validate ids"""
        def _wrapper(self, instance, value):
            if not isinstance(value, self.type):
                raise TypeError(f"Must be a {self.type}")
            if len(value) == 0:
                raise TypeError("Can't be empty")
            for i in value:
                if not isinstance(i, int):
                    raise TypeError("Must be a list of integers")
        return _wrapper

    @validate_ids_list
    def __set__(self, instance, value):
        setattr(instance, self.name, value)


class ClientsInterestsRequest:
    """ClientsInterestsRequest"""
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest:
    """OnlineScoreRequest"""
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)


class MethodRequest:
    """MethodRequest"""
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        """check for administrator"""
        return self.login == ADMIN_LOGIN


def check_auth(request):
    """check hash"""
    if request.is_admin:
        digest = hashlib.sha512(
            (datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')
            ).hexdigest()
    else:
        digest = hashlib.sha512(
            (request.account + request.login + SALT).encode('utf-8')
            ).hexdigest()
    if digest == request.token:
        return True
    return False


def online_score(request, request_obj, ctx, store):
    """method online score"""
    try:
        args_obj = OnlineScoreRequest()
        for k, val in request['body']['arguments'].items():
            cmd = f'{args_obj.__class__.__name__}().{k} = {val.__repr__()}'
            exec(cmd)
            # print(cmd)
    except Exception:
        args_obj = None
    if not args_obj:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST
    if not any((
            'phone' in request_obj.arguments and 'email' in request_obj.arguments,
            'first_name' in request_obj.arguments and 'last_name' in request_obj.arguments,
            'gender' in request_obj.arguments and 'birthday' in request_obj.arguments,
    )):
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST

    # checks are passed
    if request_obj.is_admin:
        score = int(ADMIN_SALT)
    else:
        score = scoring.get_score(
            request['body']['arguments'].get('phone', None),
            request['body']['arguments'].get('email', None),
            birthday=request['body']['arguments'].get('birthday', None),
            gender=request['body']['arguments'].get('gender', None),
            first_name=request['body']['arguments'].get('first_name', None),
            last_name=request['body']['arguments'].get('last_name', None),
        )
    ctx['has'] = request['body']['arguments'].keys()
    return {'score': float(score)}, OK


def clients_interests(request, request_obj, ctx, store):
    """method client interests"""
    try:
        args_obj = ClientsInterestsRequest()
        for k, val in request['body']['arguments'].items():
            cmd = f'{args_obj.__class__.__name__}().{k} = {val.__repr__()}'
            exec(cmd)
            # print(cmd)
    except Exception:
        # print(e)
        args_obj = None
    if not args_obj:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST
    if not 'client_ids' in request_obj.arguments:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST

    # checks are passed
    res = {}
    for identificator in request_obj.arguments['client_ids']:
        res[f'client_id{identificator}'] = scoring.get_interests()
    ctx['nclients'] = len(request_obj.arguments['client_ids'])
    return res, OK


def method_handler(request, ctx, store):
    """обработчик, который получает запрос, выдает респонс и код"""
    # test if empty
    if request['body'] == {}:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST

    # or bad request
    try:
        request_obj = MethodRequest()
        for k, val in request['body'].items():
            cmd = f'{request_obj.__class__.__name__}.{k} = {val.__repr__()}'
            exec(cmd)
    except:
        args_obj = None
        request_obj = None
    if not request_obj:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST
    if not all((
            'login' in request['body'],
            'method' in request['body'],
            'arguments' in request['body'],
    )):
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST

    # test auth
    if not check_auth(request_obj):
        return ERRORS[FORBIDDEN], FORBIDDEN

    if request['body']['arguments'] == {}:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST
    # test validation
    if request['body']['method'] == 'online_score':
        response, code = online_score(request, request_obj, ctx, store)

    elif request['body']['method'] == 'clients_interests':
        response, code = clients_interests(request, request_obj, ctx, store)

    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    """MainHTTPHandler"""
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        """Getting the id of the request"""
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        """POT method"""
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except Exception:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s", self.path, data_string, context["request_id"])
            if path in self.router:
                try:
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers},
                        context, self.store)
                except Exception as error:
                    logging.exception("Unexpected error: %s", error)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            resp = {"response": response, "code": code}
        else:
            resp = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(resp)
        logging.info(context)
        self.wfile.write((json.dumps(resp)).encode())


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info('Starting server at %s', opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
