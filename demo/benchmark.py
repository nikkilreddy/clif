#!/usr/bin/env python3
"""
Chrontinal Benchmark — 2M Log Stress Test
==========================================
Triggers a 2-million real-log benchmark on the Chrontinal SIEM pipeline.
Monitors ingestion in real-time and displays final results.

The logs are pre-loaded on the server (16 real-world datasets, 11 source types).
This script remotely triggers the test and polls for progress.

Usage:
    python benchmark.py                    # Run benchmark (8 workers)
    python benchmark.py --workers 12       # Custom worker count
    python benchmark.py --reset            # Clear tables for fresh run
    python benchmark.py --status           # Check current status
    python benchmark.py --results          # View last results

Requirements:
    pip install requests
"""
import argparse
import sys
import time

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library required.  Install: pip install requests")
    sys.exit(1)

TARGET = "http://chrontinal.com/benchmark"


def _update_target(url):
    global TARGET
    TARGET = url


class C:
    """ANSI colors."""
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"


def banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║          Chrontinal — 2M Log Benchmark Test                  ║
║          Real-World SIEM Pipeline Stress Test                ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
{C.DIM}Target: {TARGET}{C.RESET}
""")


def check_health():
    try:
        r = requests.get(f"{TARGET}/health", timeout=5)
        return r.status_code == 200
    except:
        return False


def start_benchmark(workers):
    r = requests.post(f"{TARGET}/start?workers={workers}", timeout=10)
    return r.json()


def get_status():
    r = requests.get(f"{TARGET}/status", timeout=30)
    return r.json()


def get_results():
    r = requests.get(f"{TARGET}/results", timeout=10)
    return r.json()


def reset_tables():
    r = requests.post(f"{TARGET}/reset", timeout=30)
    return r.json()


def fmt(n):
    return f"{n:,}" if isinstance(n, int) else str(n)


def progress_bar(pct, width=30):
    filled = int(width * pct / 100)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {pct:.1f}%"


def monitor_benchmark():
    """Poll status every 3 seconds and display live progress."""
    prev_phase = None
    while True:
        try:
            s = get_status()
        except Exception as e:
            print(f"  {C.RED}Connection error: {e}{C.RESET}")
            time.sleep(3)
            continue

        phase = s["phase"]
        running = s["running"]

        if phase == "idle":
            print(f"  {C.DIM}Benchmark not running.{C.RESET}")
            return False

        if phase == "loading" and prev_phase != "loading":
            print(f"\n  {C.YELLOW}📂 Loading 2M events from disk...{C.RESET}")

        if phase == "sending":
            pct = s["progress_pct"]
            eps = s["eps"]
            sent = s["sent"]
            total = s["total"]
            elapsed = s["elapsed_sec"]
            ch = s.get("clickhouse", {})
            ch_total = ch.get("total_ingested", 0)
            triage = ch.get("triage_scored", 0)

            print(f"\r  {C.GREEN}⚡ SENDING{C.RESET}  {progress_bar(pct)}  "
                  f"Sent: {fmt(sent)}/{fmt(total)}  "
                  f"EPS: {fmt(eps)}  "
                  f"CH: {fmt(ch_total)}  "
                  f"Triage: {fmt(triage)}  "
                  f"[{elapsed:.0f}s]     ", end="", flush=True)

        if phase == "processing":
            if prev_phase != "processing":
                print(f"\n\n  {C.YELLOW}⏳ Send complete. Waiting for pipeline to finish processing...{C.RESET}")

            ch = s.get("clickhouse", {})
            ch_total = ch.get("total_ingested", 0)
            triage = ch.get("triage_scored", 0)
            hunter = ch.get("hunter_investigations", 0)
            verifier = ch.get("verifier_results", 0)
            elapsed = s["elapsed_sec"]

            print(f"\r  {C.CYAN}⚙ PROCESSING{C.RESET}  "
                  f"CH: {fmt(ch_total)}  "
                  f"Triage: {fmt(triage)}  "
                  f"Hunter: {fmt(hunter)}  "
                  f"Verifier: {fmt(verifier)}  "
                  f"[{elapsed:.0f}s]     ", end="", flush=True)

        if phase == "done":
            print()
            return True

        if phase == "error":
            print(f"\n  {C.RED}ERROR: {s.get('error_msg', 'Unknown error')}{C.RESET}")
            return False

        prev_phase = phase
        time.sleep(3)


def display_results(r):
    """Pretty-print benchmark results."""
    ch = r["clickhouse"]

    # Grade color
    grade = r["grade"]
    if grade.startswith("A"):
        gc = C.GREEN
    elif grade.startswith("B"):
        gc = C.YELLOW
    else:
        gc = C.RED

    print(f"""
{C.BOLD}{'═'*64}
       CHRONTINAL 2M BENCHMARK RESULTS
{'═'*64}{C.RESET}

  {C.BOLD}Data Source:{C.RESET}        100% real logs (16 datasets, 11 source types)
  {C.BOLD}Workers:{C.RESET}            {r['workers']}

  {C.BOLD}Send Phase:{C.RESET}
    Events Sent:      {fmt(r['events_sent']):>12}
    Send Time:        {r['send_time_sec']:>11.1f}s
    Send EPS:         {fmt(r['send_eps']):>12}
    Send Errors:      {fmt(r['send_errors']):>12}

  {C.BOLD}End-to-End:{C.RESET}
    Total Time:       {r['total_time_sec']:>11.1f}s
    E2E EPS:          {fmt(r['e2e_eps']):>12}
    Data Loss:        {r['data_loss_pct']:>11.2f}%

  {C.BOLD}ClickHouse Ingested:{C.RESET}
    raw_logs:         {fmt(ch['raw_logs']):>12}
    security_events:  {fmt(ch['security_events']):>12}
    network_events:   {fmt(ch['network_events']):>12}
    process_events:   {fmt(ch['process_events']):>12}
    {C.BOLD}TOTAL:            {fmt(ch['total_ingested']):>12}{C.RESET}
    dead_letter:      {fmt(ch['dead_letter']):>12}

  {C.BOLD}AI Pipeline:{C.RESET}
    Triage Scored:    {fmt(ch['triage_scored']):>12}
    - Suspicious:     {fmt(ch['suspicious']):>12}
    - Anomalous:      {fmt(ch['anomalous']):>12}
    Hunter Investig:  {fmt(ch['hunter_investigations']):>12}
    Verifier Results: {fmt(ch['verifier_results']):>12}

  {C.BOLD}GRADE:{C.RESET}              {gc}{C.BOLD}{grade}{C.RESET}
  {C.DIM}Completed: {r['completed_at']}{C.RESET}

{C.BOLD}{'═'*64}{C.RESET}

  {C.CYAN}{C.BOLD}>>> View results on the Chrontinal Dashboard: http://chrontinal.com{C.RESET}
""")


def main():
    parser = argparse.ArgumentParser(description="Chrontinal 2M Log Benchmark")
    parser.add_argument("--target", default=TARGET, help="Benchmark service URL")
    parser.add_argument("--workers", type=int, default=8, help="Number of TCP workers (1-16)")
    parser.add_argument("--reset", action="store_true", help="Clear ClickHouse tables before run")
    parser.add_argument("--status", action="store_true", help="Check current benchmark status")
    parser.add_argument("--results", action="store_true", help="View last benchmark results")
    args = parser.parse_args()

    target_url = args.target
    # Update all functions to use the target
    _update_target(target_url)

    banner()

    # Health check
    if not check_health():
        print(f"  {C.RED}✗ Cannot reach benchmark service at {TARGET}{C.RESET}")
        print(f"  {C.DIM}  Ensure the server is running.{C.RESET}")
        sys.exit(1)
    print(f"  {C.GREEN}✓ Connected to benchmark service{C.RESET}")

    # Status only
    if args.status:
        s = get_status()
        print(f"\n  Phase: {s['phase']}")
        print(f"  Running: {s['running']}")
        if s["running"]:
            print(f"  Sent: {fmt(s['sent'])}/{fmt(s['total'])} ({s['progress_pct']:.1f}%)")
            print(f"  EPS: {fmt(s['eps'])}")
            ch = s.get("clickhouse", {})
            print(f"  ClickHouse: {fmt(ch.get('total_ingested', 0))}")
        return

    # Results only
    if args.results:
        try:
            r = get_results()
            if "error" in r:
                print(f"\n  {C.YELLOW}{r['error']}{C.RESET}")
            else:
                display_results(r)
        except Exception as e:
            print(f"\n  {C.RED}Error: {e}{C.RESET}")
        return

    # Reset
    if args.reset:
        print(f"  {C.YELLOW}🗑 Clearing ClickHouse tables...{C.RESET}")
        r = reset_tables()
        print(f"  {C.GREEN}✓ Tables cleared: {', '.join(r['tables_cleared'])}{C.RESET}\n")

    # Start benchmark
    print(f"  {C.CYAN}🚀 Starting benchmark with {args.workers} workers...{C.RESET}")
    try:
        r = start_benchmark(args.workers)
        if "error" in r:
            print(f"  {C.RED}✗ {r['error']}{C.RESET}")
            if "already running" in r["error"].lower():
                print(f"  {C.DIM}  Use --status to check progress or wait for completion.{C.RESET}")
            sys.exit(1)
    except Exception as e:
        print(f"  {C.RED}✗ Failed to start: {e}{C.RESET}")
        sys.exit(1)

    print(f"  {C.GREEN}✓ Benchmark started!{C.RESET}")
    print(f"  {C.DIM}  Ingesting ~2,000,000 real logs through the full pipeline...{C.RESET}\n")

    # Monitor progress
    success = monitor_benchmark()

    if success:
        try:
            r = get_results()
            display_results(r)
        except Exception as e:
            print(f"\n  {C.RED}Error fetching results: {e}{C.RESET}")


if __name__ == "__main__":
    main()
