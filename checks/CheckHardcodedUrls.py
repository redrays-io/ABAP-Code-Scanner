# checks/check_hardcoded_urls.py

import re
from dataclasses import dataclass
from typing import List

@dataclass
class CheckResult:
    line_number: int
    line_content: str

class CheckHardcodedUrls:
    title = "Hardcoded URLs detected"
    severity = "Medium"
    vulnerability_type = "Information Disclosure"

    def __init__(self):
        self.pattern = re.compile(
            r'\s+["\']https?://\w+.*?$',
            re.IGNORECASE| re.IGNORECASE| re.MULTILINE
        )

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        lines = file_content.split('\n')
        for i, line in enumerate(lines, 1):
            for match in self.pattern.finditer(line):
                results.append(CheckResult(i, line.strip()))
                break  # Only report one URL per line
        return results
