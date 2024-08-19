import unittest
from checks.CheckDirectoryTraversalTransfer import CheckDirectoryTraversalTransfer, CheckResult

class TestCheckDirectoryTraversalTransfer(unittest.TestCase):

    def setUp(self):
        self.checker = CheckDirectoryTraversalTransfer()

    def test_unsafe_transfer(self):
        code = "TRANSFER lv_content TO p_file."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("TRANSFER", results[0].line_content)

    def test_safe_transfer_with_validation(self):
        code = """
        CALL FUNCTION 'FILE_VALIDATE_NAME'
          EXPORTING
            logical_filename = p_file
          EXCEPTIONS
            OTHERS           = 1.
        IF sy-subrc = 0.
          TRANSFER lv_content TO p_file.
        ENDIF.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_unsafe_transfer_with_incomplete_validation(self):
        code = """
        CALL FUNCTION 'FILE_VALIDATE_NAME'
          EXPORTING
            logical_filename = p_file
          EXCEPTIONS
            OTHERS           = 1.
        TRANSFER lv_content TO p_file.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 7)

    def test_multiple_transfers(self):
        code = """
        TRANSFER content1 TO file1.
        CALL FUNCTION 'FILE_VALIDATE_NAME'
          EXPORTING
            logical_filename = file2
          EXCEPTIONS
            OTHERS           = 1.
        IF sy-subrc = 0.
          TRANSFER content2 TO file2.
        ENDIF.
        TRANSFER content3 TO file3.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)

    def test_case_insensitivity(self):
        code = "transfer lv_content to p_file."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_transfer_in_comment(self):
        code = "* TRANSFER lv_content TO p_file."
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

if __name__ == '__main__':
    unittest.main()