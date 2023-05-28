"""Test module"""
import datetime
import functools
import hashlib
import unittest
import sys
sys.path.append('/home/user/otus/project/app')

import api
import store


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
        self.settings = store.Storage()

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


    @cases([
        {"phone": "79175002040", "email": "stupnikov@otus.ru"},
        {"phone": 79175002040, "email": "stupnikov@otus.ru"},
        {"gender": 1, "birthday": "01.01.2000", "first_name": "a", "last_name": "b"},
        {"gender": 0, "birthday": "01.01.2000"},
        {"gender": 2, "birthday": "01.01.2000"},
        {"first_name": "a", "last_name": "b"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru",
         "gender": 1, "birthday": "01.01.2000",
         "first_name": "a", "last_name": "b"},
    ])
    def test_ok_score_request(self, arguments):
        """test_ok_score_request"""
        request = {"account": "horns&hoofs", "login": "h&f",
                   "method": "online_score", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.OK, code, arguments)
        score = response.get("score")
        self.assertTrue(isinstance(score, (int, float)) and score >= 0, arguments)
        self.assertEqual(sorted(self.context["has"]), sorted(arguments.keys()))

    def test_ok_score_admin_request(self):
        """test_ok_score_admin_request"""
        arguments = {"phone": "79175002040", "email": "stupnikov@otus.ru"}
        request = {"account": "horns&hoofs", "login": "admin",
                   "method": "online_score", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.OK, code)
        score = response.get("score")
        self.assertEqual(score, 42)

    @cases([
        {"client_ids": [1, 2, 3], "date": datetime.datetime.today().strftime("%d.%m.%Y")},
        {"client_ids": [1, 2], "date": "19.07.2017"},
        {"client_ids": [0]},
    ])
    def test_ok_interests_request(self, arguments):
        """test_ok_interests_request"""
        request = {"account": "horns&hoofs",
                   "login": "h&f", 
                   "method": "clients_interests", 
                   "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.OK, code, arguments)
        self.assertEqual(len(arguments["client_ids"]), len(response))
        self.assertTrue(all(
            v and isinstance(v, list) and all(isinstance(i, (bytes, str)) for i in v)
                            for v in response.values()
                            ))
        self.assertEqual(self.context.get("nclients"), len(arguments["client_ids"]))


if __name__ == "__main__":
    unittest.main()
