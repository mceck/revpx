#!/bin/bash
# Test runner script for revpx

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Configuration
PROXY_HTTPS_PORT=${PROXY_HTTPS_PORT:-8443}
PROXY_HTTP_PORT=${PROXY_HTTP_PORT:-8880}
BACKEND_PORT=${BACKEND_PORT:-9999}
CERT_FILE="test.localhost.pem"
KEY_FILE="test.localhost-key.pem"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null || true
    fi
    if [ ! -z "$REVPX_PID" ]; then
        kill $REVPX_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT

echo -e "${YELLOW}=== RevPx Test Runner ===${NC}\n"

# Build revpx if needed
if [ ! -f "./build/revpx" ]; then
    echo -e "${YELLOW}Building revpx...${NC}"
    ./nob
fi

# Check certificates
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo -e "${RED}Error: Certificate files not found!${NC}"
    echo "Expected: $CERT_FILE and $KEY_FILE"
    echo "Generate them with: mkcert test.localhost"
    exit 1
fi

# Start backend server
echo -e "${YELLOW}Starting backend server on port $BACKEND_PORT...${NC}"
python3 "$SCRIPT_DIR/backend_server.py" -p $BACKEND_PORT &
BACKEND_PID=$!
sleep 1

# Verify backend is running
if ! kill -0 $BACKEND_PID 2>/dev/null; then
    echo -e "${RED}Error: Backend server failed to start${NC}"
    exit 1
fi

# Start revpx
echo -e "${YELLOW}Starting revpx on ports $PROXY_HTTPS_PORT (HTTPS) and $PROXY_HTTP_PORT (HTTP)...${NC}"
./build/revpx -p $PROXY_HTTPS_PORT -pp $PROXY_HTTP_PORT test.localhost $BACKEND_PORT $CERT_FILE $KEY_FILE &
REVPX_PID=$!
sleep 2

# Verify revpx is running
if ! kill -0 $REVPX_PID 2>/dev/null; then
    echo -e "${RED}Error: revpx failed to start${NC}"
    exit 1
fi

echo -e "${GREEN}Servers started successfully${NC}\n"

# Run tests
if [ "$1" == "--quick" ]; then
    echo -e "${YELLOW}Running quick tests...${NC}\n"
    python3 "$SCRIPT_DIR/quick_tests.py"
elif [ "$1" == "--stress" ]; then
    echo -e "${YELLOW}Running stress tests...${NC}\n"
    python3 -m pytest "$SCRIPT_DIR/test_revpx.py" -v -k "Stress" --tb=short
elif [ ! -z "$1" ]; then
    echo -e "${YELLOW}Running specific test: $1${NC}\n"
    python3 -m pytest "$SCRIPT_DIR/test_revpx.py" -v -k "$1" --tb=short
else
    echo -e "${YELLOW}Running all tests...${NC}\n"
    python3 "$SCRIPT_DIR/quick_tests.py"
fi

echo -e "\n${GREEN}=== Tests completed ===${NC}"
