import re
from dataclasses import dataclass
from typing import List


@dataclass
class CheckResult:
    line_number: int
    line_content: str


class CheckWeakHashingAlgorithms:
    title = "Using weak hashing algorithms"
    severity = "Critical"
    vulnerability_type = "Weak Cryptography"

    def __init__(self):
        weak_algorithms = [
            "MD2", "MD4", "MD5", "MD6", "HAVAL128", "HMACMD5",
            "DSA", "SHA1", "RIPEMD", "RIPEMD128", "RIPEMD160",
            "HMACRIPEMD160"
        ]
        pattern = r"'(" + "|".join(weak_algorithms) + r")'"
        self.pattern = re.compile(pattern, re.IGNORECASE)

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        lines = file_content.split('\n')
        for i, line in enumerate(lines, 1):
            if self.pattern.search(line):
                results.append(CheckResult(i, line.strip()))
        return results
