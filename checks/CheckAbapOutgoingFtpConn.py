import re
from dataclasses import dataclass
from typing import List


@dataclass
class CheckResult:
    line_number: int
    line_content: str


class CheckAbapOutgoingFtpConn:
    title = "Insecure Outgoing FTP Connection"
    severity = "Low"
    vulnerability_type = "Unencrypted Communications"

    def __init__(self):
        self.pattern = re.compile(
            r"(\bCALL FUNCTION\b)(\s*'FTP_CONNECT'.+?\.)",
            re.DOTALL | re.IGNORECASE
        )

    def run(self, file_content: str) -> List[CheckResult]:
        match = self.pattern.search(file_content)
        if match:
            line_number = file_content[:match.start()].count('\n') + 1
            return [CheckResult(line_number, match.group().strip())]
        return []
