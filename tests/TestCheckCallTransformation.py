import unittest
from checks.CheckCallTransformation import CheckCallTransformation, CheckResult

class TestCheckCallTransformation(unittest.TestCase):

    def setUp(self):
        self.checker = CheckCallTransformation()

    def test_single_call_transformation(self):
        code = "CALL TRANSFORMATION id SOURCE data = ls_usr02 RESULT XML lv_xml."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("CALL TRANSFORMATION", results[0].line_content)

    def test_multiple_call_transformations(self):
        code = """
        FORM difficult.
          CALL TRANSFORMATION id SOURCE data = <ls_target> RESULT XML lv_xml.
        ENDFORM.
        FORM easy.
          CALL TRANSFORMATION id OPTIONS initial_components = 'suppress' SOURCE data = ls_usr02 RESULT XML lv_xml.
        ENDFORM.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 3)
        self.assertEqual(results[1].line_number, 6)

    def test_case_insensitivity(self):
        code = "call transformation id SOURCE data = ls_usr02 RESULT XML lv_xml."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_leading_whitespace(self):
        code = "    CALL TRANSFORMATION id SOURCE data = ls_usr02 RESULT XML lv_xml."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_no_call_transformation(self):
        code = """
        REPORT safe_program.
        DATA: lv_data TYPE string.
        lv_data = 'Hello, World!'.
        WRITE: lv_data.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_call_transformation_in_comment(self):
        code = "* This is a comment: CALL TRANSFORMATION should not be detected here."
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

if __name__ == '__main__':
    unittest.main()