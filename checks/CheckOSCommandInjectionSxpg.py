import re
from dataclasses import dataclass
from typing import List


@dataclass
class CheckResult:
    line_number: int
    line_content: str


class CheckOSCommandInjectionSxpg:
    title = "OS Command Injection Vulnerability in SXPG Function"
    severity = "High"
    vulnerability_type = "OS Command injection"

    def __init__(self):
        self.main_pattern = re.compile(
            r"(?sim)^\s*(CALL FUNCTION).+?\.",
            re.DOTALL | re.IGNORECASE
        )
        self.second_stage_pattern = re.compile(
            r"(SXPG_CALL_SYSTEM|SXPG_COMMAND_EXECUTE)'\s*EXPORTING\s*(\w+\s*=\s*.*?)*$",
            re.DOTALL | re.IGNORECASE
        )
        self.param_pattern = re.compile(
            r"\w+\s*=\s*(['\"]?\w+['\"]?)",
            re.IGNORECASE
        )

    def check_second_stage(self, match_text: str) -> bool:
        second_match = self.second_stage_pattern.search(match_text)
        if second_match:
            return bool(self.param_pattern.search(second_match.group()))
        return False

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        for match in self.main_pattern.finditer(file_content):
            if self.check_second_stage(match.group()):
                line_number = file_content[:match.start()].count('\n') + 1
                results.append(CheckResult(line_number, match.group().strip()))
        return results
