# checks/check_dummy_auth_check.py

import re
from dataclasses import dataclass
from typing import List


@dataclass
class CheckResult:
    line_number: int
    line_content: str


class CheckDummyAuthCheck:
    title = "Dummy AUTHORITY Checks"
    severity = "High"
    vulnerability_type = "Access Control Bypass"

    def __init__(self):
        self.main_pattern = re.compile(
            r"(?sim)^[\s]*(\bAUTHORITY-CHECK\b)(.+?\.)",
            re.DOTALL | re.IGNORECASE
        )
        self.dummy_pattern = re.compile(
            r"ID\s*'[\w+_]+'\s*DUMMY",
            re.IGNORECASE
        )
        self.actvt_pattern = re.compile(
            r"ID\s*'ACTVT'",
            re.IGNORECASE
        )

    def check_second_stage(self, match_text: str) -> bool:
        dummy_matches = list(self.dummy_pattern.finditer(match_text))
        actvt_match = self.actvt_pattern.search(match_text)

        if not dummy_matches:
            return False

        if not actvt_match:
            return True

        actvt_pos = actvt_match.start()
        for dummy_match in dummy_matches:
            if dummy_match.start() > actvt_pos:
                return True

        return False

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        for match in self.main_pattern.finditer(file_content):
            if self.check_second_stage(match.group()):
                line_number = file_content[:match.start()].count('\n') + 1
                results.append(CheckResult(line_number, match.group().strip()))
        return results

