import unittest

from checks.CheckDirectoryTraversalCallAlerts import CheckDirectoryTraversalCallAlerts


class TestCheckABAPDirectoryTraversalAlerts(unittest.TestCase):

    def setUp(self):
        self.checker = CheckDirectoryTraversalCallAlerts()

    def test_vulnerable_call_alerts(self):
        code = """
        CALL 'ALERTS'
        ID 'HANDLE' FIELD HLP_HANDLE 
        ID 'FILE_NAME' FIELD HLP_TEMSENAME
        ID 'BINARY' FIELD 'X' 
        ID 'TYPE' FIELD 'DATA'
        ID 'RECTYP' FIELD 'U------' 
        ID 'RC' FIELD _RC
        ID 'ERRMSG' FIELD ERRMSG.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)
        self.assertIn("CALL 'ALERTS'", results[0].line_content)
        self.assertIn("ID 'FILE_NAME' FIELD HLP_TEMSENAME", results[0].line_content)

    def test_non_vulnerable_call(self):
        code = """
        CALL 'ALERTS'
        ID 'HANDLE' FIELD HLP_HANDLE 
        ID 'BINARY' FIELD 'X' 
        ID 'TYPE' FIELD 'DATA'
        ID 'RECTYP' FIELD 'U------' 
        ID 'RC' FIELD _RC
        ID 'ERRMSG' FIELD ERRMSG.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_commented_vulnerable_call(self):
        code = """
        * CALL 'ALERTS'
        * ID 'HANDLE' FIELD HLP_HANDLE 
        * ID 'FILE_NAME' FIELD HLP_TEMSENAME
        * ID 'BINARY' FIELD 'X' 
        * ID 'TYPE' FIELD 'DATA'
        * ID 'RECTYP' FIELD 'U------' 
        * ID 'RC' FIELD _RC
        * ID 'ERRMSG' FIELD ERRMSG.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)

    def test_multiple_calls(self):
        code = """
        CALL 'SAFE_FUNCTION'.

        CALL 'ALERTS'
        ID 'HANDLE' FIELD HLP_HANDLE 
        ID 'FILE_NAME' FIELD HLP_TEMSENAME
        ID 'BINARY' FIELD 'X' 
        ID 'TYPE' FIELD 'DATA'
        ID 'RECTYP' FIELD 'U------' 
        ID 'RC' FIELD _RC
        ID 'ERRMSG' FIELD ERRMSG.

        CALL METHOD some_object->some_method.

        CALL 'ALERTS'
        ID 'HANDLE' FIELD HLP_HANDLE 
        ID 'BINARY' FIELD 'X' 
        ID 'TYPE' FIELD 'DATA'
        ID 'RECTYP' FIELD 'U------' 
        ID 'RC' FIELD _RC
        ID 'ERRMSG' FIELD ERRMSG. 
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 4)

    def test_case_insensitivity(self):
        code = """
        call 'alerts'
        id 'handle' field hlp_handle 
        id 'file_name' field hlp_temsename
        id 'binary' field 'x' 
        id 'type' field 'data'
        id 'rectyp' field 'u------' 
        id 'rc' field _rc
        id 'errmsg' field errmsg.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)

    def test_multiline_call(self):
        code = """
        CALL 'ALERTS'
        ID 'HANDLE' FIELD HLP_HANDLE 
        ID 'FILE_NAME' 
          FIELD HLP_TEMSENAME
        ID 'BINARY' FIELD 'X' 
        ID 'TYPE' FIELD 'DATA'
        ID 'RECTYP' FIELD 'U------' 
        ID 'RC' FIELD _RC
        ID 'ERRMSG' FIELD ERRMSG.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)


if __name__ == '__main__':
    unittest.main()
