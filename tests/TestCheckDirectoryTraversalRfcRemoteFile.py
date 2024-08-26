import unittest

from checks.CheckDirectoryTraversalRfcRemoteFile import CheckDirectoryTraversalRfcRemoteFile


class TestCheckDirectoryTraversalRfcRemoteFile(unittest.TestCase):

    def setUp(self):
        self.checker = CheckDirectoryTraversalRfcRemoteFile()

    def test_vulnerable_call(self):
        code = """
        CALL FUNCTION 'RFC_REMOTE_FILE'
          EXPORTING
            file = lv_filename
            mode = 'R'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("CALL FUNCTION 'RFC_REMOTE_FILE'", results[0].line_content)

    def test_non_vulnerable_call(self):
        code = """
        CALL FUNCTION 'SOME_OTHER_FUNCTION'
          EXPORTING
            param = value.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_calls(self):
        code = """
        CALL FUNCTION 'RFC_REMOTE_FILE'
          EXPORTING
            file = lv_filename1
            mode = 'R'.

        CALL FUNCTION 'SAFE_FUNCTION'.

        CALL FUNCTION 'RFC_REMOTE_FILE'
          EXPORTING
            file = lv_filename2
            mode = 'W'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[1].line_number, 8)

    def test_case_insensitivity(self):
        code = """
        call function 'rfc_remote_file'
          exporting
            file = lv_filename
            mode = 'R'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_multiline_call(self):
        code = """
        CALL FUNCTION 'RFC_REMOTE_FILE'
          EXPORTING
            file = 
              lv_filename
            mode = 'R'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)


if __name__ == '__main__':
    unittest.main()
