import re
from dataclasses import dataclass
from typing import List

@dataclass
class CheckResult:
    line_number: int
    line_content: str

class CheckDirectoryTraversalCallAlerts:
    title = "Path Traversal - CALL ALERTS"
    severity = "Medium"
    vulnerability_type = "Path Traversal"

    def __init__(self):
        self.pattern1 = re.compile(r"(?si)(\bCALL\b)(.+?\.)")
        self.pattern2 = re.compile(r"(?sim)'ALERTS'.*?ID\s*'FILE_NAME'\s*FIELD\s*\w+")

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        for match1 in self.pattern1.finditer(file_content):
            call_statement = match1.group()
            if self.pattern2.search(call_statement):
                line_number = file_content[:match1.start()].count('\n') + 1
                results.append(CheckResult(line_number, call_statement.strip()))
        return results