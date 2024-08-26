from dataclasses import dataclass
from typing import List

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter


@dataclass
class ScanResult:
    file_path: str
    line_number: int
    title: str
    message: str
    severity: str


def severity_key(result: ScanResult):
    severity_order = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4,
        "Info": 5
    }
    return severity_order.get(result.severity, 6)


def generate_xlsx_report(results: List[ScanResult], output_file: str):
    # Sort results by severity
    results.sort(key=severity_key)

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Scan Results"

    # Define styles
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="4F81BD", end_color="4F81BD", fill_type="solid")
    centered_alignment = Alignment(horizontal="center", vertical="center")
    wrapped_alignment = Alignment(horizontal="left", vertical="top", wrap_text=True)

    severity_colors = {
        "Critical": "FF0000",  # Red
        "High": "FFA500",  # Orange
        "Medium": "FFFF00",  # Yellow
        "Low": "90EE90",  # Light Green
        "Info": "ADD8E6"  # Light Blue
    }

    # Write headers
    headers = ["Severity", "Title", "File Path", "Line Number", "Message"]
    for col, header in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = centered_alignment

    # Write data
    for row, result in enumerate(results, start=2):
        ws.cell(row=row, column=1, value=result.severity).alignment = wrapped_alignment
        ws.cell(row=row, column=2, value=result.title).alignment = wrapped_alignment
        ws.cell(row=row, column=3, value=result.file_path).alignment = wrapped_alignment
        ws.cell(row=row, column=4, value=result.line_number).alignment = wrapped_alignment
        ws.cell(row=row, column=5, value=result.message).alignment = wrapped_alignment

        # Apply color to severity cell
        severity_cell = ws.cell(row=row, column=1)
        if result.severity in severity_colors:
            severity_cell.fill = PatternFill(start_color=severity_colors[result.severity],
                                             end_color=severity_colors[result.severity],
                                             fill_type="solid")

    # Auto-adjust column widths
    for col in range(1, len(headers) + 1):
        ws.column_dimensions[get_column_letter(col)].auto_size = True

        # Set a maximum width for the message column
        message_column = get_column_letter(headers.index("Message") + 1)
        ws.column_dimensions[message_column].width = 50  # Adjust this value as needed

        # Set a maximum width for the check name column
        title = get_column_letter(headers.index("Title") + 1)
        ws.column_dimensions[title].width = 50  # Adjust this value as needed

        # Set a maximum width for the file path column
        file_path = get_column_letter(headers.index("File Path") + 1)
        ws.column_dimensions[file_path].width = 50  # Adjust this value as needed

    # Add filters
    ws.auto_filter.ref = ws.dimensions

    # Save the workbook
    wb.save(output_file)


# Example usage
if __name__ == "__main__":
    # Sample data
    sample_results = [
        ScanResult("file1.abap", 10, "CheckCrossSiteScripting", "Potential XSS vulnerability", "High"),
        ScanResult("file2.abap", 25, "CheckHardcodedCredentials", "Hardcoded password detected", "Critical"),
        ScanResult("file1.abap", 50, "CheckOSCommandInjection", "Potential OS command injection", "High"),
        ScanResult("file3.abap", 100, "CheckWeakCrypto", "Use of weak cryptographic algorithm", "Medium"),
        ScanResult("file4.abap", 75, "CheckInfoDisclosure", "Potential information disclosure", "Low"),
    ]

    generate_xlsx_report(sample_results, "security_scan_report.xlsx")
    print("XLSX report generated successfully.")
