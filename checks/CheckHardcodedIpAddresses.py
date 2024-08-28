import re
from dataclasses import dataclass
from typing import List


@dataclass
class CheckResult:
    line_number: int
    line_content: str


class CheckHardcodedIpAddresses:
    title = "Using hardcoded IP addresses is security-sensitive"
    severity = "Low"
    vulnerability_type = "Information Disclosure"

    def __init__(self):
        # IPv4 pattern, excluding exceptions mentioned
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        # IPv6 pattern, excluding documentation addresses
        self.ipv6_pattern = re.compile(
            r'\b(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:(?:(:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b'
        )

    def is_exception(self, ip: str) -> bool:
        exceptions = [
            r'^127\.',  # Loopback
            r'^255\.255\.255\.255$',  # Broadcast
            r'^0\.0\.0\.0$',  # Non-routable
            r'^2\.5\.\d{1,3}\.\d{1,3}$',  # Potential OID
            r'^192\.0\.2\.',  # Documentation (RFC 5737)
            r'^198\.51\.100\.',  # Documentation (RFC 5737)
            r'^203\.0\.113\.',  # Documentation (RFC 5737)
            r'^2001:db8::1'  # IPv6 Documentation (RFC 3849)
        ]
        return any(re.match(pattern, ip) for pattern in exceptions)

    def run(self, file_content: str) -> List[CheckResult]:
        results = []
        lines = file_content.split('\n')
        for i, line in enumerate(lines, 1):
            ip_matches = self.ipv4_pattern.findall(line)
            ip_matches.extend(self.ipv6_pattern.findall(line))
            for ip in ip_matches:
                if isinstance(ip, tuple):  # For IPv6 matches
                    ip = ''.join(ip)
                if not self.is_exception(ip):
                    results.append(CheckResult(i, line.strip()))
                    break  # Only report one issue per line
        return results
