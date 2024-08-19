# checks/check_os_command_injection_rfc_remote_pipe.py

import re
from dataclasses import dataclass
from typing import List

@dataclass
class CheckResult:
    line_number: int
    line_content: str

class CheckOSCommandInjectionRfcRemotePipe:
    title = "Potential OS Command injection detected - RFC_REMOTE_PIPE"
    severity = "High"
    vulnerability_type = "OS Command injection"

    def __init__(self):
        self.main_pattern = re.compile(
            r"(?sim)^\s*(CALL\s+FUNCTION).+?\.",
            re.DOTALL | re.IGNORECASE
        )
        self.second_stage_pattern = re.compile(
            r"(?sim)'RFC_REMOTE_PIPE'.*?EXPORTING.*?COMMAND\s*=\s*[\w+']{1,}",
            re.DOTALL | re.IGNORECASE
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