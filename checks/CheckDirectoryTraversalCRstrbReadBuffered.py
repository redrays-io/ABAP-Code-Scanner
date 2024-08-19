import re
from dataclasses import dataclass
from typing import List

@dataclass
class CheckResult:
    line_number: int
    line_content: str

class CheckDirectoryTraversalCRstrbReadBuffered:
    title = "Path Traversal - CALL C_RSTRB_READ_BUFFERED"
    severity = "Medium"
    vulnerability_type = "Path Traversal"

    def __init__(self):
        self.pattern1 = re.compile(r"(?is)(\bCALL\b)(.+?\.)")
        self.pattern2 = re.compile(r"(?sim)'C_RSTRB_READ_BUFFERED'.*?ID\s*'name'\s*FIELD\s*\w+")

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        for match1 in self.pattern1.finditer(file_content):
            call_statement = match1.group()
            if self.pattern2.search(call_statement):
                line_number = file_content[:match1.start()].count('\n') + 1
                results.append(CheckResult(line_number, call_statement.strip()))
        return results