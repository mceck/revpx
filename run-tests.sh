#!/bin/bash

set -e
mkcert test.localhost
python3 -m pytest tests/test_revpx.py -v
