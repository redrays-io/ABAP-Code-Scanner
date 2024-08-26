import unittest

from checks.CheckHardcodedIpAddresses import CheckHardcodedIpAddresses


class TestCheckHardcodedIpAddresses(unittest.TestCase):

    def setUp(self):
        self.checker = CheckHardcodedIpAddresses()

    def test_ipv4_detection(self):
        code = "DATA: ip TYPE string VALUE '192.168.12.42'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("192.168.12.42", results[0].line_content)

    def test_ipv6_detection(self):
        code = "DATA: ipv6 TYPE string VALUE '2001:0db8:85a3:0000:0000:8a2e:0370:7334'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)
        self.assertIn("2001:0db8:85a3:0000:0000:8a2e:0370:7334", results[0].line_content)

    def test_loopback_exception(self):
        code = "DATA: loopback TYPE string VALUE '127.0.0.1'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_broadcast_exception(self):
        code = "DATA: broadcast TYPE string VALUE '255.255.255.255'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_ips(self):
        code = """
        DATA: ip1 TYPE string VALUE '192.168.1.1'.
        DATA: ip2 TYPE string VALUE '10.0.0.1'.
        DATA: safe TYPE string VALUE '127.0.0.1'.
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 2)
        self.assertEqual(results[1].line_number, 3)

    def test_ip_in_string(self):
        code = "DATA: message TYPE string VALUE 'Connected to 192.168.1.1 successfully'."
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 1)


if __name__ == '__main__':
    unittest.main()
