# tests/test_check_os_command_injection_c_function.py

import unittest
from checks.CheckOSCommandInjectionCFunction import CheckOSCommandInjectionCFunction, CheckResult

class TestCheckOSCommandInjectionCFunction(unittest.TestCase):

    def setUp(self):
        self.checker = CheckOSCommandInjectionCFunction()

    def test_vulnerable_c_function_call(self):
        code = """
        CALL 'C_FUNCTION' ID 'COMMAND' FIELD lv_command.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("CALL 'C_FUNCTION'", results[0].line_content)

    def test_non_vulnerable_system_call(self):
        code = """
        CALL 'SYSTEM' ID 'COMMAND' FIELD lv_command.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_non_vulnerable_other_excluded_calls(self):
        excluded_calls = ["ThWpInfo", "C_DB_FUNCTION", "C_DB_EXECUTE", "C_RSTRB_READ_BUFFERED", "ALERTS"]
        for call in excluded_calls:
            code = f"""
            CALL '{call}' ID 'PARAM' FIELD lv_param.
            """
            results = self.checker.run(code)
            self.assertEqual(len(results), 0, f"Failed for {call}")

    def test_multiple_vulnerable_calls(self):
        code = """
        CALL 'C_FUNCTION1' ID 'COMMAND' FIELD lv_command1.
        CALL 'SYSTEM' ID 'COMMAND' FIELD lv_command2.
        CALL 'C_FUNCTION2' ID 'PARAM' FIELD lv_param.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[1].line_number, 4)

    def test_case_insensitivity(self):
        code = """
        call 'c_function' id 'command' field lv_command.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_multiline_call(self):
        code = """
        CALL 'C_FUNCTION' 
             ID 'COMMAND' 
             FIELD lv_command.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_no_field_parameter(self):
        code = """
        CALL 'C_FUNCTION' ID 'COMMAND' VALUE 'some_command'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

if __name__ == '__main__':
    unittest.main()