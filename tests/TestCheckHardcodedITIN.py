import unittest
from checks.CheckHardcodedITIN import CheckHardcodedITIN, CheckResult

class TestCheckHardcodedITIN(unittest.TestCase):

    def setUp(self):
        self.checker = CheckHardcodedITIN()

    def test_valid_itin_with_dashes(self):
        code = "lv_itin = '999-92-5475'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("999-92-5475", results[0].line_content)

    def test_valid_itin_without_dashes(self):
        code = "lv_itin = '912785678'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("912785678", results[0].line_content)

    def test_invalid_itin(self):
        code = "lv_itin = '123456789'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_itins(self):
        code = """
        lv_itin1 = '999-92-5475'.
        lv_itin2 = '912785678'.
        lv_not_itin = '123456789'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 2)
        self.assertEqual(results[1].line_number, 3)

    def test_itin_in_string(self):
        code = "DATA: lv_string = 'This string contains an ITIN: 912785678'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)  # Note: This detects ITINs even in strings

    def test_no_itin(self):
        code = """
        REPORT z_safe_program.
        DATA: lv_result TYPE string.
        lv_result = 'Safe code here'.
        WRITE: lv_result.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

if __name__ == '__main__':
    unittest.main()