# checks/check_exposed_system_calls.py

import re
from dataclasses import dataclass
from typing import List

@dataclass
class CheckResult:
    line_number: int
    line_content: str

class CheckExposedSystemCalls:
    title = "Exposed System Call"
    severity = "High"
    vulnerability_type = "Danger System Call"

    def __init__(self):
        self.pattern = re.compile(
            r"(?smi)^[\s]*\bSYSTEM-CALL\b\s+",
            re.DOTALL | re.IGNORECASE
        )

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        for match in self.pattern.finditer(file_content):
            line_number = file_content[:match.start()].count('\n') + 1
            results.append(CheckResult(line_number, match.group().strip()))
        return results
