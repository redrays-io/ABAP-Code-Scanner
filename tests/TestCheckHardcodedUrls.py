import unittest

from checks.CheckHardcodedUrls import CheckHardcodedUrls


class TestCheckHardcodedUrls(unittest.TestCase):

    def setUp(self):
        self.checker = CheckHardcodedUrls()

    def test_http_url(self):
        code = 'lv_url = "http://example.com".'
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("http://example.com", results[0].line_content)

    def test_https_url(self):
        code = "lv_url = 'https://secure.example.com/api'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("https://secure.example.com/api", results[0].line_content)

    def test_multiple_urls(self):
        code = """
        lv_url1 = 'http://example1.com'.
        lv_url2 = "https://example2.com".
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 2)
        self.assertEqual(results[1].line_number, 3)

    def test_url_in_function_call(self):
        code = 'CALL FUNCTION "HTTP_CALL" EXPORTING URL = "https://api.example.com".'
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertIn("https://api.example.com", results[0].line_content)

    def test_no_urls(self):
        code = """
        DATA: lv_var TYPE string.
        lv_var = 'This is not a URL'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_case_insensitivity(self):
        code = 'lv_url = "HTTP://EXAMPLE.COM".'
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertIn("HTTP://EXAMPLE.COM", results[0].line_content)

    def test_multiple_urls_one_line(self):
        code = 'lv_urls = "http://example1.com" && "https://example2.com".'
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)  # Only report once per line
        self.assertIn("http://example1.com", results[0].line_content)
        self.assertIn("https://example2.com", results[0].line_content)


if __name__ == '__main__':
    unittest.main()
