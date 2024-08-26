import unittest

from checks.CheckCrossSiteScripting import CheckCrossSiteScripting


class TestCheckCrossSiteScripting(unittest.TestCase):

    def setUp(self):
        self.checker = CheckCrossSiteScripting()

    def test_positive_case(self):
        code = """
        DATA: lv_data TYPE string.
        lv_data = request->get_form_field( 'user_input' ).
        out->print_string( lv_data ).
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line_number, 4)
        self.assertIn("print_string( lv_data )", results[0].line_content)

    def test_negative_case(self):
        code = """
        DATA: lv_data TYPE string.
        lv_data = request->get_form_field( 'user_input' ).
        lv_data = escape( val = lv_data format = cl_abap_format=>e_html_attr ).
        out->print_string( lv_data ).
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)

    def test_multiple_vulnerabilities(self):
        code = """
        DATA: lv_data1 TYPE string,
              lv_data2 TYPE string.
        lv_data1 = request->get_form_field( 'input1' ).
        lv_data2 = request->get_form_field( 'input2' ).
        out->print_string( lv_data1 ).
        out->print_string( lv_data2 ).
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].line_number, 6)
        self.assertEqual(results[1].line_number, 7)

    def test_false_positive(self):
        code = """
        DATA: lv_data TYPE string.
        lv_data = 'Static string'.
        out->print_string( lv_data ).
        """
        results = self.checker.run(code)
        self.assertEqual(len(results), 0)


if __name__ == '__main__':
    unittest.main()
