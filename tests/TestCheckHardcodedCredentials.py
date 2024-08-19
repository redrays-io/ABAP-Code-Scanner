# tests/test_check_hardcoded_credentials.py

import unittest
from checks.CheckHardcodedCredentials import CheckHardcodedCredentials, CheckResult

class TestCheckHardcodedCredentials(unittest.TestCase):

    def setUp(self):
        self.checker = CheckHardcodedCredentials()

    def test_hardcoded_password(self):
        code = """
        DATA: password(10) VALUE 'secret123'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)
        self.assertIn("password(10) VALUE '", results[0].line_content)

    def test_hardcoded_pwd(self):
        code = """
        DATA: pwd(10) VALUE 'secret123'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)
        self.assertIn("pwd(10) VALUE '", results[0].line_content)

    def test_hardcoded_pass(self):
        code = """
        lv_pass = 'not_so_secret'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)
        self.assertIn("pass = '", results[0].line_content)

    def test_non_credential_assignment(self):
        code = """
        DATA: lv_name(10) VALUE 'John Doe'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_hardcoded_credentials(self):
        code = """
        DATA: password(10) VALUE 'secret123',
              pwd(10) VALUE 'another_secret'.
        lv_pass = 'not_so_secret'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0].line_number, 2)
        self.assertEqual(results[1].line_number, 3)
        self.assertEqual(results[2].line_number, 4)

    def test_case_insensitivity(self):
        code = """
        DATA: PASSWORD(10) value 'SECRET123'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)

    def test_multiline_assignment(self):
        code = """
        lv_password = 
            'multiline_secret'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)

if __name__ == '__main__':
    unittest.main()