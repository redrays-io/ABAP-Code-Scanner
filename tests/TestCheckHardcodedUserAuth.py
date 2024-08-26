import unittest

from checks.CheckHardcodedUserAuth import CheckHardcodedUserAuth


class TestCheckHardcodedUserAuth(unittest.TestCase):

    def setUp(self):
        self.checker = CheckHardcodedUserAuth()

    def test_if_sy_uname(self):
        code = "IF SY-UNAME = 'ALICE'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("IF SY-UNAME = 'ALICE'", results[0].line_content)

    def test_if_syst_uname(self):
        code = "IF SYST-UNAME EQ 'BOB'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("IF SYST-UNAME EQ 'BOB'", results[0].line_content)

    def test_case_sy_uname(self):
        code = "CASE SY-UNAME."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("CASE SY-UNAME", results[0].line_content)

    def test_case_syst_uname(self):
        code = "CASE SYST-UNAME."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("CASE SYST-UNAME", results[0].line_content)

    def test_not_equal_operator(self):
        code = "IF SY-UNAME <> 'CHARLIE'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("IF SY-UNAME <> 'CHARLIE'", results[0].line_content)

    def test_multiple_violations(self):
        code = """
        IF SY-UNAME = 'ALICE'.
        ENDIF.
        CASE SYST-UNAME.
        ENDCASE.
        IF sy-uname NE 'BOB'.
        ENDIF.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0].line_number, 2)
        self.assertEqual(results[1].line_number, 4)
        self.assertEqual(results[2].line_number, 6)

    def test_no_violation(self):
        code = """
        AUTHORITY-CHECK OBJECT 'S_TCODE'
                 ID 'TCD' FIELD sy-tcode.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_case_insensitivity(self):
        code = "if sy-uname = 'alice'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)


if __name__ == '__main__':
    unittest.main()
