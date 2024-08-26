import unittest

from checks.CheckDirectoryTraversalReadDataset import CheckDirectoryTraversalReadDataset


class TestCheckDirectoryTraversalReadDataset(unittest.TestCase):

    def setUp(self):
        self.checker = CheckDirectoryTraversalReadDataset()

    def test_vulnerable_read_dataset(self):
        code = """
        DATA: file TYPE string VALUE `flights.dat`,
              wa   TYPE spfli,
              itab LIKE TABLE OF wa.

        FIELD-SYMBOLS <hex_container> TYPE x.

        OPEN DATASET file FOR INPUT IN BINARY MODE.

        ASSIGN wa TO <hex_container> CASTING.

        DO.
          READ DATASET file INTO <hex_container>.
          IF sy-subrc = 0.
            APPEND wa TO itab.
          ELSE.
            EXIT.
          ENDIF.
        ENDDO.

        CLOSE DATASET file.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 13)
        self.assertIn("READ DATASET file", results[0].line_content)

    def test_vulnerable_read_dataset_with_maximum_length(self):
        code = """
        DATA: file TYPE string VALUE `flights.dat`,
              hex_container TYPE x LENGTH 1000,
              len TYPE i,
              itab          TYPE TABLE OF spfli.

        FIELD-SYMBOLS <spfli> TYPE spfli.

        DESCRIBE FIELD <spfli> LENGTH len IN BYTE MODE.

        OPEN DATASET file FOR INPUT IN BINARY MODE.

        ASSIGN hex_container TO <spfli> CASTING.

        DO.
          READ DATASET file INTO hex_container MAXIMUM LENGTH len.
          IF sy-subrc = 0.
            APPEND <spfli> TO itab.
          ELSE.
            EXIT.
          ENDIF.
        ENDDO.

        CLOSE DATASET file.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 16)

    def test_non_vulnerable_code(self):
        code = """
        DATA: file TYPE string VALUE `flights.dat`,
              wa   TYPE spfli,
              itab LIKE TABLE OF wa.

        OPEN DATASET file FOR INPUT IN BINARY MODE.
        CLOSE DATASET file.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_vulnerable_reads(self):
        code = """
        READ DATASET file1 INTO data1.
        WRITE: / 'Some other code'.
        READ DATASET file2 INTO data2.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 1)
        self.assertEqual(results[1].line_number, 4)

    def test_case_insensitivity(self):
        code = """
        read dataset FILE INTO data.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)


if __name__ == '__main__':
    unittest.main()
