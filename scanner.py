# scanner.py

import importlib
import os
from typing import List, NamedTuple
from tqdm import tqdm
import concurrent.futures
import chardet


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

    def scan(self, path: str, limit: int = 1000000000, num_threads: int = 48) -> List[ScanResult]:
        files_to_scan = []

        # Collect all files to scan
        if os.path.isfile(path):
            files_to_scan.append(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    if any(file.endswith(ext) for ext in self.config.get_file_extensions()):
                        files_to_scan.append(os.path.join(root, file))
                        if len(files_to_scan) >= limit:
                            break
                if len(files_to_scan) >= limit:
                    break

        # Limit the number of files to scan
        files_to_scan = files_to_scan[:limit]

        # Scan files in parallel with progress bar
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(self._scan_file, file_path) for file_path in files_to_scan]
            results = []
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(files_to_scan), desc="Scanning files", unit=" file"):
                results.extend(future.result())

        return results

    def _scan_file(self, file_path: str) -> List[ScanResult]:
        results = []
        try:
            # First, try to detect the file encoding
            with open(file_path, 'rb') as f:
                raw_data = f.read()
            detected_encoding = chardet.detect(raw_data)['encoding']

            # Try to read the file with the detected encoding
            try:
                with open(file_path, 'r', encoding=detected_encoding) as f:
                    content = f.read()
            except UnicodeDecodeError:
                # If that fails, try with 'latin-1' encoding, which should read all byte values
                with open(file_path, 'r', encoding='latin-1') as f:
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
        except Exception as e:
            print(f"Error scanning file {file_path}: {str(e)}")
        return results