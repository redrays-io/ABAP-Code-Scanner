import unittest

from checks.CheckOSCommandInjectionCallSystem import CheckOSCommandInjectionCallSystem


class TestCheckOSCommandInjectionCallSystem(unittest.TestCase):

    def setUp(self):
        self.checker = CheckOSCommandInjectionCallSystem()

    def test_vulnerable_call_system(self):
        code = """
        REPORT ztest.

        DATA:
          lv_command(50) TYPE c,
          lv_line(150)   TYPE c,
          lt_tab         LIKE TABLE OF lv_line.

        lv_command = 'ls -l'.
        CALL 'SYSTEM' ID 'COMMAND'  FIELD                  lv_command
                      ID 'TAB'     FIELD lt_tab.

        LOOP AT lt_tab INTO lv_line.
          WRITE: / lv_line.
        ENDLOOP.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 10)
        self.assertIn("CALL 'SYSTEM' ID 'COMMAND'", results[0].line_content)

    def test_non_vulnerable_call(self):
        code = """
        CALL FUNCTION 'SAFE_FUNCTION'
          EXPORTING
            param = value.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_vulnerable_calls(self):
        code = """
        CALL 'SYSTEM' ID 'COMMAND' FIELD lv_command1
                      ID 'TAB'    FIELD lt_tab1.

        " Some other code

        CALL 'SYSTEM' ID 'COMMAND' FIELD lv_command2
                      ID 'TAB'    FIELD lt_tab2.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[1].line_number, 6)

    def test_case_insensitivity(self):
        code = """
        call 'system' id 'command' field lv_command
                      id 'tab'    field lt_tab.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_multiline_call(self):
        code = """
        CALL 'SYSTEM' 
             ID 'COMMAND' 
             FIELD lv_command
             ID 'TAB'    
             FIELD lt_tab.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)


if __name__ == '__main__':
    unittest.main()
