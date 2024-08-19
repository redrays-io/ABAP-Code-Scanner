import re
from dataclasses import dataclass
from typing import List

@dataclass
class CheckResult:
    line_number: int
    line_content: str

class CheckHardcodedITIN:
    title = "Hardcoded ITIN"
    severity = "High"
    vulnerability_type = "Information Exposure"

    def __init__(self):
        self.pattern = re.compile(r'[^w0-8](?!999999999)(9\d{2})([ \-]?)(([7]\d|8[0-8])|[9][0-24-9])([ \-]?)(\d{4})[^w0-9]')

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        lines = file_content.split('\n')
        for i, line in enumerate(lines, 1):
            matches = self.pattern.findall(line)
            if matches:
                results.append(CheckResult(i, line.strip()))
        return results

