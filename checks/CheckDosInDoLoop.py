import re
from dataclasses import dataclass
from typing import List
from enum import Enum

@dataclass
class CheckResult:
    line_number: int
    line_content: str

class CheckDosInDoLoop:
    title = "Denial of Service (DOS) in do/enddo loop."
    severity = "Medium"
    vulnerability_type = "DOS"

    def __init__(self):
        self.pattern = re.compile(
            r"(?smi)^[\s]*do\s*[a-zA-Z0-9]+\w+.*?times\.",
            re.MULTILINE | re.IGNORECASE | re.DOTALL
        )

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        for match in self.pattern.finditer(file_content):
            line_number = file_content[:match.start()].count('\n') + 1
            results.append(CheckResult(line_number, match.group().strip()))
        return results

