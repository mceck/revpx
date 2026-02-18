#!/bin/bash

set -e
mkcert test.localhost
pip install pytest
python -m pytest tests/ -v

cd tests/dart
dart pub get
dart test