# checks/check_directory_traversal_rfc_remote_file.py

import re
from dataclasses import dataclass
from typing import List
from enum import Enum

@dataclass
class CheckResult:
    line_number: int
    line_content: str

class CheckDirectoryTraversalRfcRemoteFile:
    title = "Potential Path Traversal detected - RFC_REMOTE_FILE"
    severity = "HIGH"
    vulnerability_type = "Path Traversal"


    def __init__(self):
        self.main_pattern = re.compile(
            r"(?ims)^[\s]*(\bCALL FUNCTION\b)(.+?\.)",
            re.DOTALL | re.IGNORECASE
        )
        self.second_stage_pattern = re.compile(
            r"(?ims)'RFC_REMOTE_FILE'.*?EXPORTING.*?file\s*=\s*\w+",
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
