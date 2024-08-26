import re
from dataclasses import dataclass
from typing import List


@dataclass
class CheckResult:
    line_number: int
    line_content: str


class CheckOSCommandInjectionClientOS:
    title = "OS Command Injection Vulnerability in GUI Function statement"
    severity = "High"
    vulnerability_type = "OS Command injection"

    def __init__(self):
        self.pattern = re.compile(
            r"(?sim)(\bcl_gui_frontend_services=>execute\b)(.+?\.$)",
            re.DOTALL | re.IGNORECASE | re.MULTILINE
        )

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        for match in self.pattern.finditer(file_content):
            line_number = file_content[:match.start()].count('\n') + 1
            results.append(CheckResult(line_number, match.group().strip()))
        return results
