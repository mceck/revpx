#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Always run tests against the latest binary.
make -B revpx

CERT_FILE="$PROJECT_ROOT/test.localhost.pem"
KEY_FILE="$PROJECT_ROOT/test.localhost-key.pem"

# Avoid paying mkcert cost on every run.
if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
	mkcert test.localhost
fi

# Install pytest only when missing.
if ! python -c "import pytest" >/dev/null 2>&1; then
	python -m pip install -q pytest pytest-asyncio >/dev/null
fi

REVPX_TESTS=(tests/test_revpx.py)
EDGE_TESTS=(tests/test_edge_cases.py)
FUZZ_TESTS=(tests/test_fuzz.py)
MIXED_TESTS=(tests/test_mixed_ws_http.py)
ROUTING_TESTS=(tests/test_routing.py)
PYTEST_COLOR_ARGS=(--color=yes)

pids=()
PARALLEL_ACTIVE=0

run_started_at=0

revpx_started_at=0
edge_started_at=0
fuzz_started_at=0
mixed_started_at=0
routing_started_at=0

revpx_finished_at=0
edge_finished_at=0
fuzz_finished_at=0
mixed_finished_at=0
routing_finished_at=0

status_revpx=-1
status_edge=-1
status_fuzz=-1
status_mixed=-1
status_routing=-1


status_label() {
	case "$1" in
	0) printf "\033[32m%-11s\033[0m" "PASS" ;;
	130) printf "%-11s" "INTERRUPTED" ;;
	-1) printf "%-11s" "PENDING" ;;
	*) printf "\033[31m%-11s\033[0m" "FAIL" ;;
	esac
}

print_global_summary() {
	local now total_duration revpx_duration edge_duration fuzz_duration mixed_duration routing_duration
	now=$(date +%s)
	if [[ $run_started_at -eq 0 ]]; then
		run_started_at=$now
	fi

	if [[ $revpx_finished_at -eq 0 && $revpx_started_at -gt 0 ]]; then revpx_finished_at=$now; fi
	if [[ $edge_finished_at -eq 0 && $edge_started_at -gt 0 ]]; then edge_finished_at=$now; fi
	if [[ $fuzz_finished_at -eq 0 && $fuzz_started_at -gt 0 ]]; then fuzz_finished_at=$now; fi
	if [[ $mixed_finished_at -eq 0 && $mixed_started_at -gt 0 ]]; then mixed_finished_at=$now; fi
	if [[ $routing_finished_at -eq 0 && $routing_started_at -gt 0 ]]; then routing_finished_at=$now; fi

	revpx_duration=$((revpx_finished_at - revpx_started_at))
	edge_duration=$((edge_finished_at - edge_started_at))
	fuzz_duration=$((fuzz_finished_at - fuzz_started_at))
	mixed_duration=$((mixed_finished_at - mixed_started_at))
	routing_duration=$((routing_finished_at - routing_started_at))
	total_duration=$((now - run_started_at))

	echo
	echo "==== Global Parallel Test Summary ===="
	printf "%-16s %-11s %-8s\n" "Shard" "State" "Time(s)"
	printf "%-16s %s %-8s\n" "test_revpx" "$(status_label "$status_revpx")" "$revpx_duration"
	printf "%-16s %s %-8s\n" "test_edge_cases" "$(status_label "$status_edge")" "$edge_duration"
	printf "%-16s %s %-8s\n" "test_fuzz" "$(status_label "$status_fuzz")" "$fuzz_duration"
	printf "%-16s %s %-8s\n" "test_mixed_ws" "$(status_label "$status_mixed")" "$mixed_duration"
	printf "%-16s %s %-8s\n" "test_routing" "$(status_label "$status_routing")" "$routing_duration"
	echo "Total wall time: ${total_duration}s"
}

mark_unfinished_as_interrupted() {
	if [[ $status_revpx -eq -1 && $revpx_started_at -gt 0 ]]; then status_revpx=130; fi
	if [[ $status_edge -eq -1 && $edge_started_at -gt 0 ]]; then status_edge=130; fi
	if [[ $status_fuzz -eq -1 && $fuzz_started_at -gt 0 ]]; then status_fuzz=130; fi
	if [[ $status_mixed -eq -1 && $mixed_started_at -gt 0 ]]; then status_mixed=130; fi
	if [[ $status_routing -eq -1 && $routing_started_at -gt 0 ]]; then status_routing=130; fi
}

kill_descendants() {
	local parent_pid="$1"
	local child_pids
	child_pids="$(pgrep -P "$parent_pid" 2>/dev/null || true)"
	for child_pid in $child_pids; do
		kill_descendants "$child_pid"
		kill "$child_pid" >/dev/null 2>&1 || true
	done
}

kill_revpx_processes() {
	# Safety net for orphaned revpx processes started from this workspace.
	local revpx_pids
	revpx_pids="$(pgrep -f "$PROJECT_ROOT/build/revpx" 2>/dev/null || true)"
	for rp in $revpx_pids; do
		kill "$rp" >/dev/null 2>&1 || true
	done
}

cleanup_children() {
	for pid in "${pids[@]:-}"; do
		kill_descendants "$pid"
		if kill -0 "$pid" >/dev/null 2>&1; then
			kill "$pid" >/dev/null 2>&1 || true
		fi
	done
	kill_revpx_processes
}

on_interrupt() {
	echo "Stopping parallel test shards..." >&2
	if [[ $PARALLEL_ACTIVE -eq 1 ]]; then
		mark_unfinished_as_interrupted
	fi
	cleanup_children
	if [[ $PARALLEL_ACTIVE -eq 1 ]]; then
		print_global_summary
		echo "Interrupted by user (Ctrl+C)."
	fi
	exit 130
}

trap on_interrupt INT TERM
trap cleanup_children EXIT

if [[ "${REVPX_TEST_PARALLEL:-1}" == "1" ]]; then
	PARALLEL_ACTIVE=1
	run_started_at=$(date +%s)

	revpx_started_at=$(date +%s)
	python -m pytest "${REVPX_TESTS[@]}" -v "${PYTEST_COLOR_ARGS[@]}" &
	pid_revpx=$!
	pids+=("$pid_revpx")

	edge_started_at=$(date +%s)
	python -m pytest "${EDGE_TESTS[@]}" -v "${PYTEST_COLOR_ARGS[@]}" &
	pid_edge=$!
	pids+=("$pid_edge")

	fuzz_started_at=$(date +%s)
	python -m pytest "${FUZZ_TESTS[@]}" -v "${PYTEST_COLOR_ARGS[@]}" &
	pid_fuzz=$!
	pids+=("$pid_fuzz")

	mixed_started_at=$(date +%s)
	python -m pytest "${MIXED_TESTS[@]}" -v "${PYTEST_COLOR_ARGS[@]}" &
	pid_mixed=$!
	pids+=("$pid_mixed")

	routing_started_at=$(date +%s)
	python -m pytest "${ROUTING_TESTS[@]}" -v "${PYTEST_COLOR_ARGS[@]}" &
	pid_routing=$!
	pids+=("$pid_routing")

	set +e
	wait "$pid_revpx"; status_revpx=$?; revpx_finished_at=$(date +%s)
	wait "$pid_edge"; status_edge=$?; edge_finished_at=$(date +%s)
	wait "$pid_fuzz"; status_fuzz=$?; fuzz_finished_at=$(date +%s)
	wait "$pid_mixed"; status_mixed=$?; mixed_finished_at=$(date +%s)
	wait "$pid_routing"; status_routing=$?; routing_finished_at=$(date +%s)
	set -e

	print_global_summary

	if [[ $status_revpx -ne 0 || $status_edge -ne 0 || $status_fuzz -ne 0 || $status_mixed -ne 0 || $status_routing -ne 0 ]]; then
		exit 1
	fi

	# Avoid running cleanup after all shards already completed successfully.
	pids=()
	PARALLEL_ACTIVE=0
else
	python -m pytest tests/ -v "${PYTEST_COLOR_ARGS[@]}"
fi
