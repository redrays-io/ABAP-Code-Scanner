import re
from dataclasses import dataclass
from typing import List


@dataclass
class CheckResult:
    line_number: int
    line_content: str


class CheckGenerateSubroutinePool:
    title = "Arbitrary Code Execution Risk via Subroutine Pool Generation"
    severity = "High"
    vulnerability_type = "Code Injection"

    def __init__(self):
        self.pattern = re.compile(r'^\s*GENERATE\s+SUBROUTINE\s+POOL', re.IGNORECASE | re.MULTILINE)

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        lines = file_content.split('\n')
        for i, line in enumerate(lines, 1):
            if self.pattern.match(line):
                results.append(CheckResult(i, line.strip()))
        return results
