# checks/check_broken_auth_check.py

import re
from dataclasses import dataclass
from typing import List


@dataclass
class CheckResult:
    line_number: int
    line_content: str


class CheckBrokenAuthCheck:
    title = "Broken AUTH Checks"
    severity = "Medium"
    vulnerability_type = "Access Control Bypass"

    def __init__(self):
        self.main_pattern = re.compile(
            r"(?ims)^[\s]*(\bAUTHORITY-CHECK\b\s*OBJECT.+?\.)\s*(\s*IF\s*sy(st)?-subrc)?",
            re.DOTALL | re.IGNORECASE
        )

    def check_second_stage(self, match: re.Match) -> bool:
        if_subrc_pattern = re.compile(r"(?ims)^[\s]*IF\s*sy(st)?-subrc", re.IGNORECASE)
        return not if_subrc_pattern.search(match.group())

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        for match in self.main_pattern.finditer(file_content):
            if self.check_second_stage(match):
                line_number = file_content[:match.start()].count('\n') + 1
                results.append(CheckResult(line_number, match.group().strip()))
        return results
