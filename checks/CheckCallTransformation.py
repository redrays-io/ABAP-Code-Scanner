import re
from dataclasses import dataclass
from typing import List

@dataclass
class CheckResult:
    line_number: int
    line_content: str

class CheckCallTransformation:
    title = "XML Injection via \"CALL TRANSFORMATION\""
    severity = "High"
    vulnerability_type = "XML Injection"

    def __init__(self):
        self.pattern = re.compile(r'(^\s*|\.\s*)CALL\s+TRANSFORMATION', re.IGNORECASE | re.MULTILINE)

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        lines = file_content.split('\n')
        for i, line in enumerate(lines, 1):
            if self.pattern.search(line):
                results.append(CheckResult(i, line.strip()))
        return results
