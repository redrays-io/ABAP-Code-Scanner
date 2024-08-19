# tests/test_check_exposed_system_calls.py

import unittest
from checks.CheckExposedSystemCalls import CheckExposedSystemCalls, CheckResult

class TestCheckExposedSystemCalls(unittest.TestCase):

    def setUp(self):
        self.checker = CheckExposedSystemCalls()

    def test_exposed_system_call_cmdout(self):
        code = """
        SYSTEM-CALL FUNCTION 'CMDOUT'
          PARAMETERS 
            command = 'dir'
            output_length = 2000
            output = lv_output.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("SYSTEM-CALL", results[0].line_content)

    def test_exposed_system_call_execute(self):
        code = """
        SYSTEM-CALL FUNCTION 'EXECUTE'
          PARAMETERS command 'rm -rf /'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("SYSTEM-CALL", results[0].line_content)

    def test_non_vulnerable_code(self):
        code = """
        CALL FUNCTION 'SAFE_FUNCTION'
          EXPORTING
            param = value.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_exposed_system_calls(self):
        code = """
        SYSTEM-CALL FUNCTION 'CMDOUT'
          PARAMETERS 
            command = 'dir'
            output_length = 2000
            output = lv_output.

        " Some other code

        SYSTEM-CALL FUNCTION 'EXECUTE'
          PARAMETERS command 'rm -rf /'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[1].line_number, 9)

    def test_case_insensitivity(self):
        code = """
        system-call FUNCTION 'cmdout'
          parameters 
            command = 'dir'
            output_length = 2000
            output = lv_output.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_multiline_system_call(self):
        code = """
        SYSTEM-CALL 
          FUNCTION 'CMDOUT'
          PARAMETERS 
            command = 'dir'
            output_length = 2000
            output = lv_output.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

if __name__ == '__main__':
    unittest.main()