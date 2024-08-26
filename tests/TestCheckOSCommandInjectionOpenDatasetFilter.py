import unittest

from checks.CheckOSCommandInjectionOpenDatasetFilter import CheckOSCommandInjectionOpenDatasetFilter


class TestCheckOSCommandInjectionOpenDatasetFilter(unittest.TestCase):

    def setUp(self):
        self.checker = CheckOSCommandInjectionOpenDatasetFilter()

    def test_vulnerable_open_dataset(self):
        code = """
        OPEN DATASET lv_filename FOR INPUT IN BINARY MODE
          FILTER lv_filter.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("OPEN DATASET", results[0].line_content)
        self.assertIn("FILTER", results[0].line_content)

    def test_non_vulnerable_open_dataset(self):
        code = """
        OPEN DATASET lv_filename FOR INPUT IN BINARY MODE.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_vulnerable_open_datasets(self):
        code = """
        OPEN DATASET lv_file1 FOR INPUT IN BINARY MODE
          FILTER lv_filter1.

        OPEN DATASET lv_file2 FOR OUTPUT IN TEXT MODE.

        OPEN DATASET lv_file3 FOR INPUT IN BINARY MODE
          FILTER lv_filter2.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[1].line_number, 6)

    def test_case_insensitivity(self):
        code = """
        open dataset lv_filename for input in binary mode
          filter lv_filter.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_multiline_open_dataset(self):
        code = """
        OPEN DATASET lv_filename 
          FOR INPUT 
          IN BINARY MODE
          FILTER 
            lv_filter.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_filter_without_open_dataset(self):
        code = """
        DATA: lv_filter TYPE string.
        lv_filter = 'some_filter_condition'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)


if __name__ == '__main__':
    unittest.main()
