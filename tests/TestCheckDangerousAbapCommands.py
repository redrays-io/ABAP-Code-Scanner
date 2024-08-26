import unittest

from checks.CheckDangerousAbapCommands import CheckDangerousAbapCommands


class TestCheckDangerousAbapCommands(unittest.TestCase):

    def setUp(self):
        self.checker = CheckDangerousAbapCommands()

    def test_editor_call(self):
        code = "EDITOR-CALL FOR lv_text."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("EDITOR-CALL", results[0].line_content)

    def test_communication(self):
        code = "COMMUNICATION 'SOMECOMMAND' TO lv_result."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("COMMUNICATION", results[0].line_content)

    def test_safe_statement(self):
        code = "WRITE: 'Hello, World!'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_dangerous_commands(self):
        code = """
        EDITOR-CALL FOR lv_text1.
        WRITE: 'Safe statement'.
        COMMUNICATION 'COMMAND' TO lv_result.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[1].line_number, 4)

    def test_case_insensitivity(self):
        code = """
        editor-call for lv_text.
        communication 'COMMAND' to lv_result.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[1].line_number, 3)

    def test_multiline_statement(self):
        code = """
        EDITOR-CALL
          FOR lv_text
          DISPLAY-MODE.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)


if __name__ == '__main__':
    unittest.main()
