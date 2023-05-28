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


    def field_tst(self, cls, var, method):
        error = None
        class SimpleTest():
            var = cls()
        obj = SimpleTest()
        try:
            obj.var = var
        except TypeError as err:
            error = err
        method(None, error)


    def test_invalid_charfield(self):
        self.field_tst(api.CharField, 1, self.assertNotEqual)
        

    def test_valid_charfield(self):
        self.field_tst(api.CharField, 'word', self.assertEqual)


    def test_invalid_integerfield(self):
        self.field_tst(api.IntegerField, [], self.assertNotEqual)
        

    def test_valid_integerfield(self):
        self.field_tst(api.IntegerField, 101, self.assertEqual)

    
    def test_invalid_emailfield(self):
        self.field_tst(api.EmailField, '@@.com', self.assertNotEqual)
        

    def test_valid_emailfield(self):
        self.field_tst(api.EmailField, 'test@testers.com', self.assertEqual)


    def test_invalid_argumentsfield(self):
        self.field_tst(api.ArgumentsField, [1, 2, 3], self.assertNotEqual)
        

    def test_valid_argumentsfield(self):
        self.field_tst(api.ArgumentsField,
                       {'email': 'test@testers.com'},
                       self.assertEqual)

    def test_invalid_phonefield(self):
        self.field_tst(api.PhoneField, '09151313651', self.assertNotEqual)
        

    def test_valid_phonefield(self):
        self.field_tst(api.PhoneField,
                       '79151313651',
                       self.assertEqual)
        
    def test_invalid_datefield(self):
        self.field_tst(api.DateField, '00.00.0000', self.assertNotEqual)
        

    def test_valid_datefield(self):
        self.field_tst(api.DateField,
                       '01.01.2000',
                       self.assertEqual)
        

    def test_invalid_bdayfield(self):
        self.field_tst(api.BirthDayField, '00.00.0000', self.assertNotEqual)
        

    def test_valid_bdayfield(self):
        self.field_tst(api.BirthDayField,
                       '01.01.2000',
                       self.assertEqual)
        

    def test_invalid_genderfield(self):
        self.field_tst(api.GenderField, -1, self.assertNotEqual)
        

    def test_valid_genderfield(self):
        self.field_tst(api.GenderField,
                       2,
                       self.assertEqual)
        
    def test_invalid_idsfield(self):
        self.field_tst(api.ClientIDsField, {}, self.assertNotEqual)
        

    def test_valid_idsfield(self):
        self.field_tst(api.ClientIDsField,
                       [1],
                       self.assertEqual)


if __name__ == "__main__":
    unittest.main()
