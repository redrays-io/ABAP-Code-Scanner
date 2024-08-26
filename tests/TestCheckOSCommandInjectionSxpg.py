import unittest

from checks.CheckOSCommandInjectionSxpg import CheckOSCommandInjectionSxpg


class TestCheckOSCommandInjectionSxpg(unittest.TestCase):

    def setUp(self):
        self.checker = CheckOSCommandInjectionSxpg()

    def test_vulnerable_sxpg_command_execute(self):
        code = """
        CALL FUNCTION 'SXPG_COMMAND_EXECUTE'
          EXPORTING
            commandname = 'LS'
            additional_parameters = '-l'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("SXPG_COMMAND_EXECUTE", results[0].line_content)

    def test_vulnerable_sxpg_call_system(self):
        code = """
        CALL FUNCTION 'SXPG_CALL_SYSTEM'
          EXPORTING
            command = 'echo "Hello"'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("SXPG_CALL_SYSTEM", results[0].line_content)

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
        CALL FUNCTION 'SXPG_COMMAND_EXECUTE'
          EXPORTING
            commandname = 'LS'.

        CALL FUNCTION 'SAFE_FUNCTION'.

        CALL FUNCTION 'SXPG_CALL_SYSTEM'
          EXPORTING
            command = 'echo "Hello"'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[1].line_number, 7)

    def test_case_insensitivity(self):
        code = """
        call function 'sxpg_command_execute'
          exporting
            commandname = 'ls'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_multiline_call(self):
        code = """
        CALL FUNCTION 'SXPG_CALL_SYSTEM'
             EXPORTING
                  command = 'echo "Hello"'
             EXCEPTIONS
                  OTHERS = 1.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)


if __name__ == '__main__':
    unittest.main()
