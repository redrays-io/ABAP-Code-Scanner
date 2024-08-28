# scanner.py

import importlib
import os
from typing import List, NamedTuple
from tqdm import tqdm


class ScanResult(NamedTuple):
    file_path: str
    line_number: int
    title: str
    message: str
    severity: str


class Scanner:
    def __init__(self, config):
        self.config = config
        self.checks = self._load_checks()

    def _load_checks(self):
        checks = []
        for check_name in self.config.get_checks():
            module = importlib.import_module(f"checks.{check_name}")
            check_class = getattr(module, check_name)
            checks.append(check_class())
        return checks

    def scan(self, path: str) -> List[ScanResult]:
        results = []
        files_to_scan = []

        # Collect all files to scan
        if os.path.isfile(path):
            files_to_scan.append(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    if any(file.endswith(ext) for ext in self.config.get_file_extensions()):
                        files_to_scan.append(os.path.join(root, file))

        # Scan files with progress bar
        for file_path in tqdm(files_to_scan, desc="Scanning files", unit="file"):
            results.extend(self._scan_file(file_path))

        return results

    def _scan_file(self, file_path: str) -> List[ScanResult]:
        results = []
        with open(file_path, 'r') as f:
            content = f.read()
        for check in self.checks:
            check_results = check.run(content)
            for result in check_results:
                results.append(ScanResult(
                    file_path=file_path,
                    line_number=result.line_number,
                    title=check.title,
                    message=result.line_content,
                    severity=check.severity
                ))
        return results