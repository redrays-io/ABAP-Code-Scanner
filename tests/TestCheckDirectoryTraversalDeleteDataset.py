# tests/test_check_directory_traversal_delete_dataset.py

import unittest
from checks.CheckDirectoryTraversalDeleteDataset import CheckDirectoryTraversalDeleteDataset, CheckResult

class TestCheckDirectoryTraversalDeleteDataset(unittest.TestCase):

    def setUp(self):
        self.checker = CheckDirectoryTraversalDeleteDataset()

    def test_vulnerable_delete_dataset(self):
        code = """
        DATA: file TYPE string VALUE `sensitive_data.dat`.

        DELETE DATASET file.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 3)
        self.assertIn("DELETE DATASET file", results[0].line_content)

    def test_vulnerable_delete_dataset_with_condition(self):
        code = """
        DATA: file TYPE string VALUE `temp_file.dat`.

        IF sy-subrc = 0.
          DELETE DATASET file FROM position.
        ENDIF.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 5)
        self.assertIn("DELETE DATASET file", results[0].line_content)

    def test_non_vulnerable_code(self):
        code = """
        DATA: file TYPE string VALUE `safe_file.dat`.

        OPEN DATASET file FOR OUTPUT IN BINARY MODE.
        CLOSE DATASET file.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_vulnerable_deletes(self):
        code = """
        DELETE DATASET file1.
        WRITE: / 'Some other code'.
        DELETE DATASET file2 FROM 10.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[1].line_number, 4)

    def test_case_insensitivity(self):
        code = """
        delete dataset FILE.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_delete_dataset_with_options(self):
        code = """
        DATA: file TYPE string VALUE `data_file.dat`.

        DELETE DATASET file NOINIT.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 3)
        self.assertIn("DELETE DATASET file", results[0].line_content)

if __name__ == '__main__':
    unittest.main()