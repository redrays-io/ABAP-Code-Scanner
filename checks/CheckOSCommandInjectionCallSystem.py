# checks/check_os_command_injection_call_system.py

import re
from dataclasses import dataclass
from typing import List


@dataclass
class CheckResult:
    line_number: int
    line_content: str


class CheckOSCommandInjectionCallSystem:
    title = "Potential OS Command injection detected - CALL SYSTEM"
    severity = "High"
    vulnerability_type = "OS Command injection"

    def __init__(self):
        self.main_pattern = re.compile(r"(?smi)^[\s]*(CALL).+?\.", re.DOTALL | re.IGNORECASE)
        self.second_stage_pattern = re.compile(
            r"(?smi)'SYSTEM'\s*ID\s*'COMMAND'\s*FIELD\s*\w+",
            re.DOTALL | re.IGNORECASE | re.MULTILINE
        )

    def check_second_stage(self, match_text: str) -> bool:
        return bool(self.second_stage_pattern.search(match_text))

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        for match in self.main_pattern.finditer(file_content):
            if self.check_second_stage(match.group()):
                line_number = file_content[:match.start()].count('\n') + 1
                results.append(CheckResult(line_number, match.group().strip()))
        return results
