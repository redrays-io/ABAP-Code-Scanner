import unittest

from checks.CheckDeleteDynpro import CheckDeleteDynpro


class TestCheckDeleteDynpro(unittest.TestCase):

    def setUp(self):
        self.checker = CheckDeleteDynpro()

    def test_single_delete_dynpro(self):
        code = "DELETE DYNPRO."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[0].line_content, "DELETE DYNPRO.")

    def test_multiple_delete_dynpro(self):
        code = """
        REPORT z_test_program.

        DELETE DYNPRO.

        WRITE: 'Hello, World!'.

          DELETE DYNPRO.

        END-OF-SELECTION.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 4)
        self.assertEqual(results[1].line_number, 8)

    def test_case_insensitivity(self):
        code = "delete dynpro."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[0].line_content, "delete dynpro.")

    def test_leading_whitespace(self):
        code = "    DELETE DYNPRO."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[0].line_content, "DELETE DYNPRO.")

    def test_no_delete_dynpro(self):
        code = """
        REPORT z_safe_program.

        WRITE: 'Hello, World!'.

        END-OF-SELECTION.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_delete_dynpro_in_comment(self):
        code = "* This is a comment: DELETE DYNPRO should not be detected here."
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)


if __name__ == '__main__':
    unittest.main()
