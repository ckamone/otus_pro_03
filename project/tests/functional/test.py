"""Test module"""
import datetime
import functools
import hashlib
import unittest
import sys
sys.path.append('/home/user/otus/project/app')

import api


def cases(cases):
    """Декоратор для запуска тесткейса с несколькими параметрами"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args):
            for case in cases:
                new_args = args + (case if isinstance(case, tuple) else (case,))
                try:
                    func(*new_args)
                except AssertionError:
                    raise AssertionError(f'{new_args}')

        return wrapper

    return decorator


class TestSuite(unittest.TestCase):
    """Класс с тестами"""
    def setUp(self):
        """Настройка перед тестами"""
        self.context = {}
        self.headers = {}
        self.settings = {}

    def get_response(self, request):
        """получаем респонс"""
        return api.method_handler(
            {"body": request, "headers": self.headers},
            self.context,
            self.settings
            )

    def set_valid_auth(self, request):
        """Генерим токен"""
        if request.get("login") == api.ADMIN_LOGIN:
            request["token"] = hashlib.sha512(
                (
                datetime.datetime.now().strftime("%Y%m%d%H") + api.ADMIN_SALT
                ).encode('utf-8')).hexdigest()
        else:
            msg = request.get("account", "") + request.get("login", "") + api.SALT
            request["token"] = hashlib.sha512(msg.encode('utf-8')).hexdigest()

    def test_empty_request(self):
        """Проверка на пустой запрос"""
        _, code = self.get_response({})
        self.assertEqual(api.INVALID_REQUEST, code)

    @cases([
        {"account": "horns&hoofs", "login": "h&f",
         "method": "online_score", "token": "", "arguments": {}},
        {"account": "horns&hoofs", "login": "h&f",
         "method": "online_score", "token": "sdd", "arguments": {}},
        {"account": "horns&hoofs", "login": "admin",
         "method": "online_score", "token": "", "arguments": {}},
    ])
    def test_bad_auth(self, request):
        """Проверка с неправильной аутентификацией"""
        _, code = self.get_response(request)
        self.assertEqual(api.FORBIDDEN, code)

    @cases([
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score"},
        {"account": "horns&hoofs", "login": "h&f", "arguments": {}},
        {"account": "horns&hoofs", "method": "online_score", "arguments": {}},
    ])
    def test_invalid_method_request(self, request):
        """Проверка с неправильным запросом method_request"""
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)
        self.assertTrue(len(response))

    @cases([
        {},
        {"phone": "79175002040"},
        {"phone": "89175002040", "email": "stupnikov@otus.ru"},
        {"phone": "79175002040", "email": "stupnikovotus.ru"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": -1},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": "1"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru",
         "gender": 1, "birthday": "01.01.1890"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "XXX"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru",
         "gender": 1, "birthday": "01.01.2000", "first_name": 1},
        {"phone": "79175002040", "email": "stupnikov@otus.ru",
         "gender": 1, "birthday": "01.01.2000",
         "first_name": "s", "last_name": 2},
        {"phone": "79175002040", "birthday": "01.01.2000", "first_name": "s"},
        {"email": "stupnikov@otus.ru", "gender": 1, "last_name": 2},
    ])
    def test_invalid_score_request(self, arguments):
        """test_invalid_score_request"""
        request = {"account": "horns&hoofs", "login": "h&f",
                   "method": "online_score", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code, arguments)
        self.assertTrue(len(response))

    @cases([
        {},
        {"date": "20.07.2017"},
        {"client_ids": [], "date": "20.07.2017"},
        {"client_ids": {1: 2}, "date": "20.07.2017"},
        {"client_ids": ["1", "2"], "date": "20.07.2017"},
        {"client_ids": [1, 2], "date": "XXX"},
    ])
    def test_invalid_interests_request(self, arguments):
        """test_invalid_interests_request"""
        request = {"account": "horns&hoofs",
                   "login": "h&f", 
                   "method": "clients_interests", 
                   "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code, arguments)
        self.assertTrue(len(response))

if __name__ == "__main__":
    unittest.main()
