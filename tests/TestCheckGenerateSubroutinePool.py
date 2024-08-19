import unittest
from checks.CheckGenerateSubroutinePool import CheckGenerateSubroutinePool, CheckResult

class TestCheckGenerateSubroutinePool(unittest.TestCase):

    def setUp(self):
        self.checker = CheckGenerateSubroutinePool()

    def test_generate_subroutine_pool_detection(self):
        code = "GENERATE SUBROUTINE POOL lv_code."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("GENERATE SUBROUTINE POOL", results[0].line_content)

    def test_multiple_occurrences(self):
        code = """
        GENERATE SUBROUTINE POOL lv_code1.
        WRITE: 'First pool generated'.
        GENERATE SUBROUTINE POOL lv_code2.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 2)
        self.assertEqual(results[1].line_number, 4)

    def test_case_insensitivity(self):
        code = "generate subroutine pool lv_code."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_leading_whitespace(self):
        code = "    GENERATE SUBROUTINE POOL lv_code."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_no_vulnerability(self):
        code = """
        REPORT z_safe_program.
        DATA: lv_result TYPE string.
        lv_result = 'Safe code here'.
        WRITE: lv_result.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_comment_line(self):
        code = "* GENERATE SUBROUTINE POOL lv_code."
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_mid_line_occurrence(self):
        code = "DATA: lv_code. GENERATE SUBROUTINE POOL lv_code."
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

if __name__ == '__main__':
    unittest.main()