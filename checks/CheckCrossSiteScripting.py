# checks/CheckCrossSiteScripting.py

import re
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class CheckResult:
    line_number: int
    line_content: str

class CheckCrossSiteScripting:
    title = "Potential Cross-Site Scripting vulnerability"
    severity = "High"
    vulnerability_type = "Cross-Site Scripting"

    def __init__(self):
        self.assignment_pattern = re.compile(
            r"(\w+)\s*=\s*request\s*->\s*get_form_field\s*\([^)]*\)",
            re.IGNORECASE
        )
        self.print_pattern = re.compile(
            r"out\s*->\s*print_string\s*\(\s*([^)]+)\s*\)",
            re.IGNORECASE
        )
        self.escape_pattern = re.compile(
            r"(\w+)\s*=\s*escape\s*\(\s*val\s*=\s*(\w+)",
            re.IGNORECASE
        )

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        lines = file_content.split('\n')
        vulnerable_vars: Dict[str, int] = {}
        escaped_vars: Dict[str, int] = {}

        # Find all assignments of get_form_field values to variables
        for i, line in enumerate(lines, 1):
            for match in self.assignment_pattern.finditer(line):
                variable = match.group(1)
                vulnerable_vars[variable] = i

        # Find all escaped variables
        for i, line in enumerate(lines, 1):
            for match in self.escape_pattern.finditer(line):
                escaped_var = match.group(1)
                source_var = match.group(2)
                if source_var in vulnerable_vars:
                    escaped_vars[escaped_var] = i
                    if source_var in vulnerable_vars:
                        del vulnerable_vars[source_var]

        # Check for usage of vulnerable variables in print_string
        for i, line in enumerate(lines, 1):
            print_match = self.print_pattern.search(line)
            if print_match:
                used_vars = re.findall(r'\b(\w+)\b', print_match.group(1))
                for var in used_vars:
                    if var in vulnerable_vars and var not in escaped_vars:
                        results.append(CheckResult(i, line.strip()))
                        break  # Stop searching after finding the first vulnerability in the line

        return results