import re
from dataclasses import dataclass
from typing import List


@dataclass
class CheckResult:
    line_number: int
    line_content: str


class CheckHardcodedUserAuth:
    title = "Insecure Authorization: Hardcoded User Property Dependency"
    severity = "Critical"
    vulnerability_type = "Insecure Authorization"

    def __init__(self):
        self.pattern = re.compile(
            r"(?sim)IF\s+(SY|SYST)-UNAME\s+(=|EQ|<>|NE)\s+['\"].*?$",
            re.IGNORECASE | re.MULTILINE
        )
        self.case_pattern = re.compile(
            r"(?sim)CASE\s+(SY|SYST)-UNAME\.",
            re.IGNORECASE | re.MULTILINE
        )

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        lines = file_content.split('\n')

        for i, line in enumerate(lines, 1):
            if self.pattern.search(line) or self.case_pattern.search(line):
                results.append(CheckResult(i, line.strip()))

        return results
