import re
from dataclasses import dataclass
from typing import List

@dataclass
class CheckResult:
    line_number: int
    line_content: str

class CheckDirectoryTraversalTransfer:
    title = "Directory traversal via \"TRANSFER\" statement"
    severity = "High"
    vulnerability_type = "Directory Traversal"

    def __init__(self):
        self.transfer_pattern = re.compile(r'(^\s*|\.\s*)TRANSFER\s+[\S]+\s+TO\s+(\w+)\.?', re.IGNORECASE | re.MULTILINE)
        self.validation_pattern = re.compile(r'CALL\s+FUNCTION\s+(\'|\`)FILE_VALIDATE_NAME(\'|\`)', re.IGNORECASE)
        self.subrc_check_pattern = re.compile(r'(IF\s+sy(st)?-subrc\s*(=|EQ)\s*0|CHECK\s+sy(st)?-subrc\s*(=|EQ)\s*0)', re.IGNORECASE)

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        lines = file_content.split('\n')
        for i, line in enumerate(lines, 1):
            transfer_match = self.transfer_pattern.search(line)
            if transfer_match:
                filename_var = transfer_match.group(2)
                if not self.is_filename_validated(file_content, filename_var):
                    results.append(CheckResult(i, line.strip()))
        return results

    def is_filename_validated(self, file_content: str, filename_var: str) -> bool:
        # Check if FILE_VALIDATE_NAME is called with the filename variable
        validation_call = re.search(rf'CALL\s+FUNCTION\s+(\'|\`)FILE_VALIDATE_NAME(\'|\`).*?{filename_var}', file_content, re.IGNORECASE | re.DOTALL)
        if validation_call:
            # Check if there's a proper subrc check after the validation
            validation_pos = validation_call.start()
            subrc_check = self.subrc_check_pattern.search(file_content[validation_pos:])
            if subrc_check:
                return True
        return False
