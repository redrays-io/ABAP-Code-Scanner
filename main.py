# main.py

import argparse
from email.policy import default

from scanner import Scanner
from config import Config
from generate_xlsx_report import generate_xlsx_report, ScanResult


def main():
    parser = argparse.ArgumentParser(description="ABAP Code Scanner")
    #parser.add_argument("path", default=r"C:\Users\admin\Desktop\research\SAP_ABAP_DEMO_CODE", help="Path to the ABAP code directory or file")
    parser.add_argument("-c", "--config", help="Path to configuration file", default="config.yml")
    args = parser.parse_args()

    config = Config(args.config)
    scanner = Scanner(config)

    results = scanner.scan(r"C:\Users\admin\Desktop\research\SAP_ABAP_DEMO_CODE") #args.path)

    # Convert scanner results to ScanResult objects, now including severity
    report_results = [
        ScanResult(
            file_path=result.file_path,
            line_number=result.line_number,
            check_name=result.check_name,
            message=result.message,
            severity=result.severity  # Make sure your scanner provides this information
        ) for result in results
    ]

    # Generate the XLSX report
    generate_xlsx_report(report_results, "abap_security_scan_report.xlsx")

    print("Scan complete. XLSX report generated: abap_security_scan_report.xlsx")

    """ for result in results:
        print(f"{result.file_path}\r\nLine:{result.line_number} - {result.check_name}: {result.message}")
    """

if __name__ == "__main__":
    main()