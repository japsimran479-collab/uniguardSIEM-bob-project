"""
UniGuard SIEM — Traffic Generator / Test Script
================================================
Companion script to visually test the UniGuard SIEM dashboard.

Menus
-----
  1. Normal Traffic Simulator  — random successful student logins sent at a
                                  configurable interval so the dashboard shows
                                  a healthy green baseline.
  2. Brute-Force Trigger       — 8 rapid FAIL requests from the same SrcIP
                                  within 2 seconds; enough to trip the >5-in-
                                  2-min alert and flip the dashboard red.
  0. Exit

Usage
-----
  python test_traffic.py                  # connects to http://127.0.0.1:5000
  python test_traffic.py --url http://... # custom target
"""

import argparse
import random
import sys
import time

try:
    import requests
except ImportError:
    sys.exit(
        "\n[ERROR] 'requests' is not installed.\n"
        "        Run:  pip install requests\n"
    )

# ── ANSI colour helpers ────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"

def clr(text, colour): return f"{colour}{text}{RESET}"

# ── Static data pools ──────────────────────────────────────────────────────────
STUDENT_IDS    = [f"stud_{random.randint(1000, 9999)}" for _ in range(40)]
WORKSTATIONS   = [f"lab-pc-{n:02d}" for n in range(1, 21)]
SUBNETS        = ["10.10", "10.11", "10.12", "192.168.1", "172.16.5"]
LOG_SOURCES    = ["UniLab", "LibPC", "AdminBlock", "SciLab", "EngLab"]

def random_src_ip():
    subnet = random.choice(SUBNETS)
    return f"{subnet}.{random.randint(2, 254)}"

def build_log(status: str, user: str, src_ip: str, workstation: str,
              log_source: str = "UniLab") -> str:
    return (
        f'LogSource="{log_source}" '
        f'Status="{status}" '
        f'User="{user}" '
        f'SrcIP="{src_ip}" '
        f'Workstation="{workstation}"'
    )

# ── HTTP helper ────────────────────────────────────────────────────────────────
def post_log(base_url: str, raw: str) -> dict | None:
    """POST a single raw log string; return the parsed JSON response or None."""
    try:
        resp = requests.post(
            f"{base_url}/api/logs",
            json={"raw": raw},
            timeout=5,
        )
        return resp.json()
    except requests.exceptions.ConnectionError:
        print(clr(
            f"\n[CONNECTION ERROR] Cannot reach {base_url}\n"
            "  → Make sure app.py is running:  python app.py\n",
            RED,
        ))
        return None
    except Exception as exc:
        print(clr(f"[ERROR] {exc}", RED))
        return None

def print_result(raw: str, data: dict | None, index: int | None = None):
    """Pretty-print one log send result."""
    prefix = f"  [{index:>3}]" if index is not None else "      "
    if data is None:
        print(clr(f"{prefix} ✗  (no response)", RED))
        return

    status  = data.get("parsed", {}).get("status", "?")
    user    = data.get("parsed", {}).get("user",   "?")
    src_ip  = data.get("parsed", {}).get("src_ip", "?")
    alert   = data.get("alert",  False)

    colour  = RED if status == "FAIL" else GREEN
    a_tag   = clr(" ⚠  ALERT TRIGGERED", RED + BOLD) if alert else ""

    print(
        f"{prefix} "
        f"{clr(status, colour):<20} "   # padded for alignment (includes ANSI codes)
        f"user={clr(user, CYAN):<30} "
        f"ip={clr(src_ip, YELLOW)}"
        f"{a_tag}"
    )

# ── Menu 1 — Normal Traffic Simulator ─────────────────────────────────────────
def menu_normal_traffic(base_url: str):
    print(clr("\n╔══ Normal Traffic Simulator ══════════════════════════════╗", CYAN))
    print(clr( "║  Sends random SUCCESS logins at a configurable interval. ║", CYAN))
    print(clr( "╚══════════════════════════════════════════════════════════╝\n", CYAN))

    try:
        count_str    = input("  How many log events to send? [default: 30] ").strip()
        interval_str = input("  Delay between each (seconds)? [default: 1.5] ").strip()
    except KeyboardInterrupt:
        print(clr("\n  ↩  Cancelled.\n", DIM))
        return

    count    = int(count_str)    if count_str.isdigit()              else 30
    interval = float(interval_str) if interval_str.replace(".", "", 1).isdigit() else 1.5

    print(clr(
        f"\n  Sending {count} events every {interval}s → {base_url}/api/logs\n"
        f"  Press Ctrl+C to stop early.\n",
        DIM,
    ))
    print(f"  {'IDX':<6} {'STATUS':<12} {'USER':<22} SOURCE IP")
    print(f"  {'───':<6} {'──────':<12} {'────':<22} ─────────")

    sent = 0
    try:
        for i in range(1, count + 1):
            user        = random.choice(STUDENT_IDS)
            src_ip      = random_src_ip()
            workstation = random.choice(WORKSTATIONS)
            log_source  = random.choice(LOG_SOURCES)
            raw         = build_log("SUCCESS", user, src_ip, workstation, log_source)
            data        = post_log(base_url, raw)
            if data is None:
                break
            print_result(raw, data, index=i)
            sent += 1
            if i < count:
                time.sleep(interval)
    except KeyboardInterrupt:
        print(clr("\n  ↩  Stopped by user.", DIM))

    print(clr(f"\n  ✓ Normal traffic done — {sent} events sent.\n", GREEN))


# ── Menu 2 — Brute-Force Trigger ──────────────────────────────────────────────
def menu_bruteforce(base_url: str):
    ATTACKER_IP  = "10.199.45.12"
    ATTACKER_USER = "admin_root"
    BURST_COUNT  = 8
    BURST_DELAY  = 0.20   # seconds between each shot → 8 × 0.20 s = 1.6 s total

    print(clr("\n╔══ Brute-Force Trigger ════════════════════════════════════╗", RED + BOLD))
    print(clr( "║  Fires 8 rapid FAIL requests from the same SrcIP         ║", RED))
    print(clr( "║  to breach the >5-in-2-min threshold and flip the        ║", RED))
    print(clr( "║  dashboard to a flashing RED alert.                      ║", RED))
    print(clr( "╚══════════════════════════════════════════════════════════╝\n", RED))
    print(f"  Target IP  : {clr(ATTACKER_IP, YELLOW)}")
    print(f"  User       : {clr(ATTACKER_USER, CYAN)}")
    print(f"  Burst size : {clr(str(BURST_COUNT), RED)} requests")
    print(f"  Interval   : {BURST_DELAY}s  (total ≈ {BURST_COUNT * BURST_DELAY:.1f}s)\n")

    try:
        confirm = input("  Ready? Press Enter to fire, or Ctrl+C to cancel… ")
    except KeyboardInterrupt:
        print(clr("\n  ↩  Cancelled.\n", DIM))
        return

    print(clr(f"\n  🔴 Firing {BURST_COUNT}× FAIL bursts NOW…\n", RED + BOLD))
    print(f"  {'IDX':<6} {'STATUS':<12} {'USER':<22} SOURCE IP")
    print(f"  {'───':<6} {'──────':<12} {'────':<22} ─────────")

    workstations = random.sample(WORKSTATIONS, min(BURST_COUNT, len(WORKSTATIONS)))

    for i in range(1, BURST_COUNT + 1):
        ws  = workstations[(i - 1) % len(workstations)]
        raw = build_log("FAIL", ATTACKER_USER, ATTACKER_IP, ws)
        data = post_log(base_url, raw)
        if data is None:
            break
        print_result(raw, data, index=i)
        if i < BURST_COUNT:
            time.sleep(BURST_DELAY)

    print(clr(
        "\n  ✓ Burst complete!\n"
        "  → Switch to your browser — the Alerts Panel should now be\n"
        "    flashing RED with a brute-force warning for 10.199.45.12.\n"
        "  → The panel clears automatically after 2 minutes of no new\n"
        "    FAIL events from that IP (rolling window).\n",
        YELLOW,
    ))


# ── Main menu ──────────────────────────────────────────────────────────────────
def main_menu(base_url: str):
    banner = f"""
{clr('╔══════════════════════════════════════════════════════════╗', CYAN + BOLD)}
{clr('║', CYAN)}   {clr('UniGuard SIEM', BOLD)} — Traffic Generator / Test Script           {clr('║', CYAN)}
{clr('║', CYAN)}   Target: {clr(base_url, YELLOW):<51}{clr('║', CYAN)}
{clr('╠══════════════════════════════════════════════════════════╣', CYAN)}
{clr('║', CYAN)}                                                          {clr('║', CYAN)}
{clr('║', CYAN)}   {clr('[1]', GREEN + BOLD)} Normal Traffic Simulator                          {clr('║', CYAN)}
{clr('║', CYAN)}       Random SUCCESS logins — green baseline on dash     {clr('║', CYAN)}
{clr('║', CYAN)}                                                          {clr('║', CYAN)}
{clr('║', CYAN)}   {clr('[2]', RED + BOLD)} Brute-Force Trigger                               {clr('║', CYAN)}
{clr('║', CYAN)}       8 rapid FAILs → dashboard flips red                {clr('║', CYAN)}
{clr('║', CYAN)}                                                          {clr('║', CYAN)}
{clr('║', CYAN)}   {clr('[0]', DIM)} Exit                                               {clr('║', CYAN)}
{clr('╚══════════════════════════════════════════════════════════╝', CYAN + BOLD)}
"""
    MENU_DISPATCH = {
        "1": menu_normal_traffic,
        "2": menu_bruteforce,
    }

    while True:
        print(banner)
        try:
            choice = input("  Choose an option: ").strip()
        except KeyboardInterrupt:
            print(clr("\n\n  Bye!\n", DIM))
            sys.exit(0)

        if choice == "0":
            print(clr("\n  Bye!\n", DIM))
            sys.exit(0)
        elif choice in MENU_DISPATCH:
            MENU_DISPATCH[choice](base_url)
            input(clr("  Press Enter to return to the main menu…", DIM))
        else:
            print(clr(f"\n  Unknown option '{choice}'. Try 1, 2, or 0.\n", YELLOW))


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="UniGuard SIEM — Traffic Generator / Test Script",
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:5000",
        help="Base URL of the running UniGuard SIEM server (default: http://127.0.0.1:5000)",
    )
    args = parser.parse_args()

    # Strip trailing slash for clean URL concatenation
    base_url = args.url.rstrip("/")

    main_menu(base_url)
