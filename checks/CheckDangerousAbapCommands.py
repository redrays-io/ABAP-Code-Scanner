import re
from dataclasses import dataclass
from typing import List


@dataclass
class CheckResult:
    line_number: int
    line_content: str


class CheckDangerousAbapCommands:
    title = "High-Risk ABAP Statement Usage"
    severity = "Medium"
    vulnerability_type = "Validation Required"

    def __init__(self):
        self.pattern = re.compile(
            r"(?sim)^\s*(\bEDITOR-CALL|COMMUNICATION\b)(.+?\.)",
            re.DOTALL | re.IGNORECASE
        )

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        for match in self.pattern.finditer(file_content):
            line_number = file_content[:match.start()].count('\n') + 1
            results.append(CheckResult(line_number, match.group().strip()))
        return results
