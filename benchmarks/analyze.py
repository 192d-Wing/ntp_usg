#!/usr/bin/env python3
"""
Analyze NTP benchmark results and generate statistics

Usage:
    python3 analyze.py results/*.csv
    python3 analyze.py results/client-accuracy-*.csv --metric offset
"""

import sys
import csv
import argparse
from pathlib import Path
from collections import defaultdict
import statistics


def load_csv(filepath):
    """Load CSV file and return list of dictionaries"""
    data = []
    with open(filepath) as f:
        reader = csv.DictReader(f)
        for row in reader:
            data.append(row)
    return data


def analyze_client_accuracy(files):
    """Analyze client accuracy (offset and jitter)"""
    results = {}

    for filepath in files:
        data = load_csv(filepath)
        impl = data[0]['implementation'] if data else Path(filepath).stem.split('-')[-1]

        offsets = [float(r['value']) for r in data if r['metric'] == 'offset']
        jitters = [float(r['value']) for r in data if r['metric'] == 'jitter']

        if offsets:
            results[impl] = {
                'offset_mean': statistics.mean(offsets),
                'offset_median': statistics.median(offsets),
                'offset_stdev': statistics.stdev(offsets) if len(offsets) > 1 else 0,
                'offset_min': min(offsets),
                'offset_max': max(offsets),
                'jitter_mean': statistics.mean(jitters) if jitters else 0,
                'jitter_median': statistics.median(jitters) if jitters else 0,
            }

    # Print results
    print("Client Accuracy Results")
    print("=" * 80)
    print(f"{'Implementation':<15} {'Mean Offset':<15} {'Median':<15} {'Jitter':<15}")
    print("-" * 80)

    for impl in sorted(results.keys()):
        r = results[impl]
        print(f"{impl:<15} {r['offset_mean']*1e6:>10.2f} µs  {r['offset_median']*1e6:>10.2f} µs  "
              f"{r['jitter_mean']*1e6:>10.2f} µs")

    print()
    return results


def analyze_throughput(files):
    """Analyze server throughput"""
    results = {}

    for filepath in files:
        data = load_csv(filepath)
        impl = data[0]['implementation'] if data else Path(filepath).stem.split('-')[-1]

        # Find max stable QPS (< 1% packet loss)
        stable = [r for r in data if float(r.get('packet_loss_percent', 100)) < 1.0]

        if stable:
            max_qps = max(int(r['qps']) for r in stable)
            max_row = next(r for r in stable if int(r['qps']) == max_qps)

            results[impl] = {
                'max_qps': max_qps,
                'response_time': float(max_row.get('response_time_ms', 0)),
                'cpu': float(max_row.get('cpu_percent', 0)),
                'memory': float(max_row.get('memory_mb', 0)),
            }

    # Print results
    print("Server Throughput Results")
    print("=" * 80)
    print(f"{'Implementation':<15} {'Max QPS':<12} {'Response':<12} {'CPU':<10} {'Memory':<10}")
    print("-" * 80)

    for impl in sorted(results.keys()):
        r = results[impl]
        print(f"{impl:<15} {r['max_qps']:>10,}  {r['response_time']:>8.2f} ms  "
              f"{r['cpu']:>6.1f}%  {r['memory']:>7.1f} MB")

    print()
    return results


def analyze_resources(files):
    """Analyze resource usage"""
    results = {}

    for filepath in files:
        data = load_csv(filepath)
        impl = data[0]['implementation'] if data else Path(filepath).stem.split('-')[-1]

        # Group by load level
        by_load = defaultdict(list)
        for row in data:
            load = int(row['load_qps'])
            by_load[load].append(row)

        results[impl] = {}
        for load in sorted(by_load.keys()):
            rows = by_load[load]
            cpu_vals = [float(r['cpu_percent']) for r in rows]
            mem_vals = [float(r['memory_rss_mb']) for r in rows]

            results[impl][load] = {
                'cpu': statistics.mean(cpu_vals),
                'memory': statistics.mean(mem_vals),
            }

    # Print results
    print("Resource Usage Results")
    print("=" * 80)

    for impl in sorted(results.keys()):
        print(f"\n{impl}:")
        print(f"  {'Load':<12} {'CPU (avg)':<12} {'Memory (avg)':<12}")
        print(f"  {'-'*40}")

        for load in sorted(results[impl].keys()):
            r = results[impl][load]
            load_str = "Idle" if load == 0 else f"{load:,} QPS"
            print(f"  {load_str:<12} {r['cpu']:>8.1f}%  {r['memory']:>10.1f} MB")

    print()
    return results


def analyze_stratum1(files):
    """Analyze Stratum 1 accuracy"""
    results = {}

    for filepath in files:
        data = load_csv(filepath)
        impl = data[0]['implementation'] if data else Path(filepath).stem.split('-')[-1]

        pps_offsets = []
        for row in data:
            try:
                pps = float(row['pps_offset_us'])
                if pps < 100000:  # Filter invalid data
                    pps_offsets.append(pps)
            except:
                pass

        if pps_offsets:
            results[impl] = {
                'mean': statistics.mean(pps_offsets),
                'median': statistics.median(pps_offsets),
                'stdev': statistics.stdev(pps_offsets) if len(pps_offsets) > 1 else 0,
                'min': min(pps_offsets),
                'max': max(pps_offsets),
            }

    # Print results
    print("Stratum 1 Accuracy Results (GPS+PPS)")
    print("=" * 80)
    print(f"{'Implementation':<15} {'Mean':<12} {'Median':<12} {'Stdev':<12} {'Max':<12}")
    print("-" * 80)

    for impl in sorted(results.keys()):
        r = results[impl]
        print(f"{impl:<15} {r['mean']:>8.2f} µs  {r['median']:>8.2f} µs  "
              f"{r['stdev']:>8.2f} µs  {r['max']:>8.2f} µs")

    print()
    return results


def main():
    parser = argparse.ArgumentParser(description='Analyze NTP benchmark results')
    parser.add_argument('files', nargs='+', help='CSV files to analyze')
    parser.add_argument('--type', choices=['client', 'throughput', 'resources', 'stratum1'],
                        help='Test type (auto-detected if not specified)')

    args = parser.parse_args()

    # Auto-detect test type from filenames
    if args.type:
        test_type = args.type
    else:
        first_file = Path(args.files[0]).name
        if 'client-accuracy' in first_file:
            test_type = 'client'
        elif 'throughput' in first_file:
            test_type = 'throughput'
        elif 'resources' in first_file:
            test_type = 'resources'
        elif 'stratum1' in first_file:
            test_type = 'stratum1'
        else:
            print("Error: Cannot auto-detect test type. Use --type", file=sys.stderr)
            return 1

    # Analyze based on type
    if test_type == 'client':
        analyze_client_accuracy(args.files)
    elif test_type == 'throughput':
        analyze_throughput(args.files)
    elif test_type == 'resources':
        analyze_resources(args.files)
    elif test_type == 'stratum1':
        analyze_stratum1(args.files)

    return 0


if __name__ == '__main__':
    sys.exit(main())
