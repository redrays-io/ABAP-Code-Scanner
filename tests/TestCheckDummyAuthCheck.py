# tests/test_check_dummy_auth_check.py

import unittest
from checks.CheckDummyAuthCheck import CheckDummyAuthCheck, CheckResult

class TestCheckDummyAuthCheck(unittest.TestCase):

    def setUp(self):
        self.checker = CheckDummyAuthCheck()

    def test_dummy_auth_check(self):
        code = """
        AUTHORITY-CHECK OBJECT 'S_TCODE'
                 ID 'TCD' DUMMY.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("AUTHORITY-CHECK", results[0].line_content)
        self.assertIn("DUMMY", results[0].line_content)

    def test_non_dummy_auth_check(self):
        code = """
        AUTHORITY-CHECK OBJECT 'S_USER_GRP'
                 ID 'CLASS' FIELD lv_class
                 ID 'ACTVT' FIELD '01'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_dummy_auth_check_with_actvt(self):
        code = """
        AUTHORITY-CHECK OBJECT 'S_USER_GRP'
                 ID 'CLASS' DUMMY
                 ID 'ACTVT' FIELD '01'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_dummy_auth_checks(self):
        code = """
        AUTHORITY-CHECK OBJECT 'S_TCODE'
                 ID 'TCD' DUMMY.

        AUTHORITY-CHECK OBJECT 'S_USER_GRP'
                 ID 'CLASS' DUMMY
                 ID 'ACTVT' FIELD '01'.

        AUTHORITY-CHECK OBJECT 'S_RFC'
                 ID 'RFC_NAME' DUMMY.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[1].line_number, 8)

    def test_case_insensitivity(self):
        code = """
        authority-check OBJECT 's_tcode'
                 id 'tcd' dummy.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_multiline_auth_check(self):
        code = """
        AUTHORITY-CHECK 
            OBJECT 'S_TCODE'
            ID 'TCD' 
            DUMMY.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

if __name__ == '__main__':
    unittest.main()