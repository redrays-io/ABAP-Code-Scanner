@echo off
set PYTHONPATH=%PYTHONPATH%;%cd%
pytest tests/ -v --cov=./ --cov-report=xml