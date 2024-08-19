# tests/test_check_os_command_injection_client_os.py

import unittest
from checks.CheckOSCommandInjectionClientOS import CheckOSCommandInjectionClientOS, CheckResult

class TestCheckOSCommandInjectionClientOS(unittest.TestCase):

    def setUp(self):
        self.checker = CheckOSCommandInjectionClientOS()

    def test_vulnerable_execute_call(self):
        code = """
        CALL METHOD cl_gui_frontend_services=>execute
        EXPORTING
        application = 'c:\windows\system32\mspaint.exe'
        parameter = lv_parameter
        synchronous = 'X'
        EXCEPTIONS
        cntl_error = 1
        rror_no_gui = 2
        bad_parameter = 3
        file_not_found = 4
        path_not_found = 5
        file_extension_unknown = 6
        error_execute_failed = 7
        synchronous_failed = 8
        not_supported_by_gui = 9
        OTHERS = 10.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)
        self.assertIn("cl_gui_frontend_services=>execute", results[0].line_content)

    def test_non_vulnerable_code(self):
        code = """
        DATA: lv_parameter TYPE string.
        CONCATENATE '"' 'c:\mypic.gif' '"' INTO lv_parameter.
        CONCATENATE '/p' lv_parameter INTO lv_parameter SEPARATED BY space.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_vulnerable_calls(self):
        code = """
        CALL METHOD cl_gui_frontend_services=>execute
        EXPORTING
        application = 'notepad.exe'
        parameter = lv_parameter1.

        " Some other code

        CALL METHOD cl_gui_frontend_services=>execute
        EXPORTING
        application = 'calc.exe'
        parameter = lv_parameter2.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 2)
        self.assertEqual(results[1].line_number, 9)

    def test_case_insensitivity(self):
        code = """
        call method CL_GUI_FRONTEND_SERVICES=>EXECUTE
        exporting
        application = 'notepad.exe'
        parameter = lv_parameter.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)

    def test_multiline_call(self):
        code = """
        CALL METHOD 
             cl_gui_frontend_services=>execute
        EXPORTING
             application = 'notepad.exe'
             parameter = lv_parameter.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 3)

if __name__ == '__main__':
    unittest.main()