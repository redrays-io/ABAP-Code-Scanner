# tests/test_check_abap_outgoing_ftp_conn.py

import unittest
from checks.CheckAbapOutgoingFtpConn import CheckAbapOutgoingFtpConn, CheckResult

class TestCheckAbapOutgoingFtpConn(unittest.TestCase):

    def setUp(self):
        self.checker = CheckAbapOutgoingFtpConn()

    def test_ftp_connect(self):
        code = """
        CALL FUNCTION 'FTP_CONNECT'
          EXPORTING
            host           = lv_host
            port           = lv_port
            user           = lv_user
            password       = lv_password
          IMPORTING
            handle         = lv_handle
          EXCEPTIONS
            not_connected  = 1
            OTHERS         = 2.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)
        self.assertIn("CALL FUNCTION 'FTP_CONNECT'", results[0].line_content)

    def test_safe_function_call(self):
        code = "CALL FUNCTION 'SAFE_FUNCTION'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_ftp_connects(self):
        code = """
        CALL FUNCTION 'FTP_CONNECT'.
        CALL FUNCTION 'SAFE_FUNCTION'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)

    def test_case_insensitivity(self):
        code = "call function 'ftp_connect'.foo."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)

    def test_multiline_function_call(self):
        code = """
        CALL FUNCTION 'FTP_CONNECT'
          EXPORTING
            host = lv_host.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 2)

if __name__ == '__main__':
    unittest.main()