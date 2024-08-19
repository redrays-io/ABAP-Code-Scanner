import re
from dataclasses import dataclass
from typing import List
from enum import Enum


@dataclass
class CheckResult:
    line_number: int
    line_content: str

class CheckHardcodedCredentials:
    title = "Hard-coded credentials are security-sensitive"
    severity = "High"
    vulnerability_type = "Hard-coded credentials"

    def __init__(self):
        self.pattern = re.compile(
            r"(?si)(?:[-_]?)(password|passwd|pass|pwd)\b(?:\(\d+\))?\s+(VALUE|=)\s+'",
            re.IGNORECASE | re.DOTALL
        )

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        for match in self.pattern.finditer(file_content):
            line_number = file_content[:match.start()].count('\n') + 1
            results.append(CheckResult(line_number, match.group().strip()))
        return results
