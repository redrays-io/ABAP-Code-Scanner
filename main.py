# main.py

import argparse

from config import Config
from generate_xlsx_report import generate_xlsx_report, ScanResult
from scanner import Scanner


def main():
    parser = argparse.ArgumentParser(description="ABAP Code Scanner")
    parser.add_argument("path", help="Path to the ABAP code directory or file")
    parser.add_argument("-c", "--config", help="Path to configuration file", default="config.yml")
    parser.add_argument("-t", "--threads", type=int, help="Number of threads to use for scanning", default=48)
    args = parser.parse_args()

    config = Config(args.config)
    scanner = Scanner(config)

    results = scanner.scan(args.path, num_threads=args.threads)

    # Convert scanner results to ScanResult objects, now including severity
    report_results = [
        ScanResult(
            file_path=result.file_path,
            line_number=result.line_number,
            title=result.title,
            message=result.message,
            severity=result.severity
        ) for result in results
    ]

    # Generate the XLSX report
    generate_xlsx_report(report_results, "abap_security_scan_report.xlsx")

    print(f"Scan complete. XLSX report generated: abap_security_scan_report.xlsx")


if __name__ == "__main__":
    main()