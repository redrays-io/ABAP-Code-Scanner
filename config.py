# config.py

import yaml


class Config:
    def __init__(self, config_file):
        with open(config_file, 'r') as f:
            self.config = yaml.safe_load(f)

    def get_checks(self):
        return self.config.get('checks', [])

    def get_file_extensions(self):
        return self.config.get('file_extensions', ['.abap'])

    def get_exclude_patterns(self):
        return self.config.get('exclude_patterns', [])
