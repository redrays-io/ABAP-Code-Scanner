# tests/test_check_os_command_injection_rfc_remote_pipe.py

import unittest
from checks.CheckOSCommandInjectionRfcRemotePipe import CheckOSCommandInjectionRfcRemotePipe, CheckResult

class TestCheckOSCommandInjectionRfcRemotePipe(unittest.TestCase):

    def setUp(self):
        self.checker = CheckOSCommandInjectionRfcRemotePipe()


    def test_vulnerable_rfc_remote_pipe(self):
        code = """
        CALL FUNCTION 'RFC_REMOTE_PIPE' DESTINATION DEST
               EXPORTING
                         COMMAND = 'ls -l'
              TABLES
                         PIPEDATA = TABLE
              EXCEPTIONS
                SYSTEM_FAILURE        = 2.
           ENDIF.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("CALL FUNCTION 'RFC_REMOTE_PIPE'", results[0].line_content)
        self.assertIn("COMMAND = 'ls -l'", results[0].line_content)

    def test_non_vulnerable_call(self):
        code = """
        CALL FUNCTION 'SAFE_FUNCTION'
          EXPORTING
            PARAM = VALUE.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_vulnerable_calls(self):
        code = """
        CALL FUNCTION 'RFC_REMOTE_PIPE' DESTINATION DEST1
               EXPORTING
                         COMMAND = 'CMD1'
              TABLES
                         PIPEDATA = TABLE1.

        CALL FUNCTION 'SAFE_FUNCTION'.

        CALL FUNCTION 'RFC_REMOTE_PIPE' DESTINATION DEST2
               EXPORTING
                         COMMAND = 'CMD2'
              TABLES
                         PIPEDATA = TABLE2.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[1].line_number, 9)

    def test_case_insensitivity(self):
        code = """
        call function 'rfc_remote_pipe' destination dest
               exporting
                         command = 'ls -l'
              tables
                         pipedata = table.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_multiline_call(self):
        code = """
        CALL FUNCTION 'RFC_REMOTE_PIPE'
             DESTINATION DEST
             EXPORTING
                  COMMAND = 'ls -l'
             TABLES
                  PIPEDATA = TABLE.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

if __name__ == '__main__':
    unittest.main()