import re
from dataclasses import dataclass
from typing import List


@dataclass
class CheckResult:
    line_number: int
    line_content: str


class CheckDirectoryTraversalDeleteDataset:
    title = "Directory Traversal Vulnerability in DELETE DATASET"
    severity = "High"
    vulnerability_type = "Path Traversal"

    def __init__(self):
        self.pattern = re.compile(
            r"(?ims)^[\s]*DELETE\s+DATASET\s*[\w0-9-]+"
        )

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        for match in self.pattern.finditer(file_content):
            line_number = file_content[:match.start()].count('\n') + 1
            results.append(CheckResult(line_number, match.group().strip()))
        return results
