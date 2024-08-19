# tests/test_check_dos_in_do_loop.py

import unittest
from checks.CheckDosInDoLoop import CheckDosInDoLoop, CheckResult

class TestCheckDosInDoLoop(unittest.TestCase):

    def setUp(self):
        self.checker = CheckDosInDoLoop()

    def test_vulnerable_do_loop_constant(self):
        code = """
        DO 1000000 TIMES.
          " Some code
        ENDDO.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("DO 1000000 TIMES", results[0].line_content)

    def test_vulnerable_do_loop_variable(self):
        code = """
        DO lv_large_number TIMES.
          " Some code
        ENDDO.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("DO lv_large_number TIMES", results[0].line_content)

    def test_non_vulnerable_code(self):
        code = """
        LOOP AT itab INTO wa.
          " Some code
        ENDLOOP.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_vulnerable_loops(self):
        code = """
        DO 1000000 TIMES.
          " Some code
        ENDDO.

        " Some other code

        DO lv_another_large_number TIMES.
          " More code
        ENDDO.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[1].line_number, 7)

    def test_case_insensitivity(self):
        code = """
        do 1000000 times.
          " Some code
        enddo.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_multiline_do_statement(self):
        code = """
        DO lv_large_number 
           TIMES.
          " Some code
        ENDDO.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

if __name__ == '__main__':
    unittest.main()