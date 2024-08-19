# tests/test_check_directory_traversal_c_rstrb_read_buffered.py

import unittest
from checks.CheckDirectoryTraversalCRstrbReadBuffered import CheckDirectoryTraversalCRstrbReadBuffered, CheckResult
class TestCheckDirectoryTraversalCRstrbReadBuffered(unittest.TestCase):

    def setUp(self):
        self.checker = CheckDirectoryTraversalCRstrbReadBuffered()

    def test_vulnerable_call(self):
        code = """
        CALL 'C_RSTRB_READ_BUFFERED'
            ID 'NAME' FIELD HLP_TEMSENAME.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)

    def test_non_vulnerable_call(self):
        code = """
        CALL 'C_RSTRB_READ_BUFFERED'
            ID 'NAME22' FIELD HLP_TEMSENAME
            ID 'NAME2' FIELD HLP_TEMSENAME.

        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_calls(self):
        code = """
        CALL 'SAFE_FUNCTION'.

        CALL 'C_RSTRB_READ_BUFFERED'
            ID 'NAME' FIELD HLP_TEMSENAME


        CALL some_object->some_method.

        CALL 'C_RSTRB_READ_BUFFERED'
            ID    = 'OTHER_ID'
            FIELD = lv_other_field.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 4)

    def test_case_insensitivity(self):
        code = """
        call 'c_rstrb_read_buffered'
            ID 'NAME' FIELD HLP_TEMSENAME.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)

if __name__ == '__main__':
    unittest.main()