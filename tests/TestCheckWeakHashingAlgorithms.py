import unittest

from checks.CheckWeakHashingAlgorithms import CheckWeakHashingAlgorithms


class TestCheckWeakHashingAlgorithms(unittest.TestCase):

    def setUp(self):
        self.checker = CheckWeakHashingAlgorithms()

    def test_all_weak_algorithms(self):
        weak_algorithms = [
            "MD2", "MD4", "MD5", "MD6", "HAVAL128", "HMACMD5",
            "DSA", "SHA1", "RIPEMD", "RIPEMD128", "RIPEMD160",
            "HMACRIPEMD160"
        ]
        for algo in weak_algorithms:
            code = f"DATA: lv_algorithm TYPE string VALUE '{algo}'."
            results = self.checker.run(code)
            self.assertEqual(len(results), 1, f"Failed to detect {algo}")
            self.assertEqual(results[0].line_number, 1)
            self.assertIn(algo, results[0].line_content)

    def test_safe_algorithm(self):
        code = "DATA: lv_algorithm TYPE string VALUE 'SHA256'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_weak_hash_algorithms(self):
        code = """
        DATA: lv_algo1 TYPE string VALUE 'MD5',
              lv_algo2 TYPE string VALUE 'SHA256',
              lv_algo3 TYPE string VALUE 'SHA1'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 2)
        self.assertEqual(results[1].line_number, 4)

    def test_case_insensitivity(self):
        code = "DATA: lv_algorithm TYPE string VALUE 'md5'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_no_false_positives(self):
        code = """
        DATA: lv_var_md5 TYPE string.
        lv_var_md5 = 'This is not an algorithm name'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)


if __name__ == '__main__':
    unittest.main()
