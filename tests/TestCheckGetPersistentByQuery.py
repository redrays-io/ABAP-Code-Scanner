import unittest
from checks.CheckGetPersistentByQuery import CheckGetPersistentByQuery, CheckResult

class TestCheckGetPersistentByQuery(unittest.TestCase):

    def setUp(self):
        self.checker = CheckGetPersistentByQuery()

    def test_get_persistent_by_query_detection(self):
        code = "lo_persistency->get_persistent_by_query( EXPORTING i_query = lv_query IMPORTING e_result = lt_result )."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("get_persistent_by_query", results[0].line_content)

    def test_multiple_occurrences(self):
        code = """
        lo_persistency->get_persistent_by_query( EXPORTING i_query = lv_query1 IMPORTING e_result = lt_result1 ).
        WRITE: 'First query executed'.
        lo_persistency->get_persistent_by_query( EXPORTING i_query = lv_query2 IMPORTING e_result = lt_result2 ).
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 2)
        self.assertEqual(results[1].line_number, 4)

    def test_case_insensitivity(self):
        code = "lo_persistency->GET_PERSISTENT_BY_QUERY( EXPORTING i_query = lv_query IMPORTING e_result = lt_result )."
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
        code = "* This is a comment mentioning get_persistent_by_query("
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)  # Note: This detects the method call even in comments

    def test_method_in_string(self):
        code = "DATA: lv_string = 'This string contains get_persistent_by_query('."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)  # Note: This detects the method call even in strings

if __name__ == '__main__':
    unittest.main()