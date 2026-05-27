#!/usr/bin/env python3
"""Iron Dome load testing baseline.

Benchmarks sandbox throughput, latency, and resource usage under
various profiles and command types. Results are saved as JSON for
tracking over time.

Usage:
    python3 scripts/load_test.py
    python3 scripts/load_test.py --iterations 100 --timeout 10
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from typing import Any

from irondome import __version__
from irondome.l3.engine import sandbox_run
from irondome.l4.engine import create_default_engine
from irondome.l4.profiler import profile_from_sandbox_result


def benchmark_scan(
    command: list[str],
    iterations: int = 10,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Benchmark a single scan command over multiple iterations."""
    durations: list[float] = []
    exit_codes: list[int] = []
    event_counts: list[int] = []
    finding_counts: list[int] = []
    errors: list[str] = []

    for i in range(iterations):
        try:
            start = time.monotonic()
            sandbox_result = sandbox_run(
                command=command,
                timeout=timeout,
                deterministic=True,
            )
            elapsed = (time.monotonic() - start) * 1000

            # L4 analysis
            engine = create_default_engine()
            profile = profile_from_sandbox_result(sandbox_result)
            analysis = engine.analyze(profile, deterministic=True)

            durations.append(elapsed)
            exit_codes.append(sandbox_result.exit_code)
            event_counts.append(len(sandbox_result.events))
            finding_counts.append(len(analysis.findings))

        except Exception as e:
            errors.append(str(e))

    # Compute stats
    result: dict[str, Any] = {
        "command": command,
        "iterations": iterations,
        "errors": len(errors),
        "latency": {},
        "events": {},
        "findings": {},
    }

    if durations:
        result["latency"] = {
            "p50": round(statistics.median(durations), 1),
            "p95": round(sorted(durations)[int(len(durations) * 0.95)], 1)
            if len(durations) >= 2
            else round(durations[0], 1),
            "p99": round(sorted(durations)[int(len(durations) * 0.99)], 1)
            if len(durations) >= 2
            else round(durations[0], 1),
            "mean": round(statistics.mean(durations), 1),
            "min": round(min(durations), 1),
            "max": round(max(durations), 1),
            "stdev": round(statistics.stdev(durations), 1) if len(durations) >= 2 else 0,
        }
        result["events"] = {
            "mean": round(statistics.mean(event_counts), 1),
            "max": max(event_counts),
        }
        result["findings"] = {
            "mean": round(statistics.mean(finding_counts), 1),
            "max": max(finding_counts),
        }

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Iron Dome load testing")
    parser.add_argument("--iterations", "-n", type=int, default=10, help="Iterations per benchmark")
    parser.add_argument("--timeout", "-t", type=float, default=30.0, help="Timeout in seconds")
    parser.add_argument("--output", "-o", type=str, default="", help="Output JSON file")
    args = parser.parse_args()

    benchmarks = [
        (["echo", "hello"], "echo-hello"),
        (["python3", "-c", "print('hello')"], "python-print"),
        (["python3", "-c", "import sys; sys.exit(0)"], "python-exit0"),
        (["python3", "-c", "x=sum(range(1000)); print(x)"], "python-compute"),
        (["python3", "-c", "import json; print(json.dumps({'a':1}))"], "python-json"),
    ]

    results: dict[str, Any] = {
        "version": __version__,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "iterations": args.iterations,
        "timeout": args.timeout,
        "benchmarks": {},
    }

    print(f"Iron Dome Load Test — v{__version__}")
    print(f"Iterations: {args.iterations}, Timeout: {args.timeout}s")
    print()

    for command, label in benchmarks:
        print(f"  Benchmarking: {label} ({' '.join(command)})")
        result = benchmark_scan(command, iterations=args.iterations, timeout=args.timeout)
        results["benchmarks"][label] = result

        if result["latency"]:
            lat = result["latency"]
            print(
                f"    p50={lat['p50']:.1f}ms  p95={lat['p95']:.1f}ms  p99={lat['p99']:.1f}ms  mean={lat['mean']:.1f}ms"
            )
        else:
            print(f"    FAILED ({result['errors']} errors)")

    print()
    output = json.dumps(results, indent=2, sort_keys=True, default=str)
    print(output)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
