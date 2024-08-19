import unittest
from checks.CheckExecuteProcedure import CheckExecuteProcedure, CheckResult

class TestCheckExecuteProcedure(unittest.TestCase):

    def setUp(self):
        self.checker = CheckExecuteProcedure()

    def test_execute_procedure_detection(self):
        code = "lo_sql_statement->execute_procedure( EXPORTING procedure = lv_query )."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("execute_procedure", results[0].line_content)

    def test_multiple_occurrences(self):
        code = """
        lo_sql_statement1->execute_procedure( EXPORTING procedure = lv_query1 ).
        WRITE: 'First procedure executed'.
        lo_sql_statement2->execute_procedure( EXPORTING procedure = lv_query2 ).
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 2)
        self.assertEqual(results[1].line_number, 4)

    def test_case_insensitivity(self):
        code = "lo_sql_statement->EXECUTE_PROCEDURE( EXPORTING procedure = lv_query )."
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
        code = "* This is a comment mentioning execute_procedure("
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)  # Note: This detects the method call even in comments

    def test_method_in_string(self):
        code = "DATA: lv_string = 'This string contains execute_procedure('."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)  # Note: This detects the method call even in strings

if __name__ == '__main__':
    unittest.main()