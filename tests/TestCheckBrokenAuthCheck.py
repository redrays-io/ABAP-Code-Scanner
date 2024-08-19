# tests/test_check_broken_auth_check.py

import unittest
from checks.CheckBrokenAuthCheck import CheckBrokenAuthCheck, CheckResult

class TestCheckBrokenAuthCheck(unittest.TestCase):

    def setUp(self):
        self.checker = CheckBrokenAuthCheck()

    def test_broken_auth_check(self):
        code = """
        AUTHORITY-CHECK OBJECT 'S_TCODE'
                 ID 'TCD' FIELD sy-tcode.
        " No IF sy-subrc check
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_correct_auth_check(self):
        code = """
        AUTHORITY-CHECK OBJECT 'S_TCODE'
                 ID 'TCD' FIELD sy-tcode.
        IF sy-subrc <> 0.
          " Handle unauthorized access
        ENDIF.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_fully_commented_auth_check(self):
        code = """
        * AUTHORITY-CHECK OBJECT 'V_VBAK_AAT'
        *   ID 'AUART' FIELD ls_vbak-auart
        *   ID 'ACTVT' FIELD lc_act_print.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_partially_commented_auth_check(self):
        code = """
        AUTHORITY-CHECK OBJECT 'V_VBAK_AAT'
        *   ID 'AUART' FIELD ls_vbak-auart
            ID 'ACTVT' FIELD lc_act_print.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_multiple_auth_checks(self):
        code = """
        AUTHORITY-CHECK OBJECT 'S_TCODE'
                 ID 'TCD' FIELD sy-tcode.
        IF sy-subrc <> 0.
          " Handle unauthorized access
        ENDIF.

        AUTHORITY-CHECK OBJECT 'V_VBAK_AAT'
                 ID 'ACTVT' FIELD lc_act_print.
        " This one is broken

        * AUTHORITY-CHECK OBJECT 'COMMENTED'
        *        ID 'TEST' FIELD test_field.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 7)

    def test_auth_check_with_syst_subrc(self):
        code = """
        AUTHORITY-CHECK OBJECT 'S_TCODE'
                 ID 'TCD' FIELD sy-tcode.
        IF syst-subrc <> 0.
          " Handle unauthorized access
        ENDIF.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

if __name__ == '__main__':
    unittest.main()