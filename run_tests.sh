#!/bin/bash
export PYTHONPATH=$PYTHONPATH:$(pwd)
pytest tests/ -v --cov=./ --cov-report=xml