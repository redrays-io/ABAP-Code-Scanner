import re
from dataclasses import dataclass
from typing import List

@dataclass
class CheckResult:
    line_number: int
    line_content: str

class CheckDeleteDynpro:
    title = "Critical actions via deleting a screen"
    severity = "High"
    vulnerability_type = "Denial of Service"

    def __init__(self):
        self.pattern = re.compile(r'^\s*DELETE\s+DYNPRO', re.IGNORECASE | re.MULTILINE)

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        lines = file_content.split('\n')
        for i, line in enumerate(lines, 1):
            if self.pattern.search(line):
                results.append(CheckResult(i, line.strip()))
        return results
