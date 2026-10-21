"""
UniGuard SIEM — File Injector
==============================
Reads 'university_access.log' line by line and streams each entry to the
UniGuard SIEM /api/logs endpoint via HTTP POST, simulating a live feed.

Usage
-----
    python file_injector.py                   # default: http://127.0.0.1:5000
    python file_injector.py --url http://...  # custom target
    python file_injector.py --delay 1.0       # custom delay in seconds
"""

import argparse
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit(
        "\n[ERROR] 'requests' library is not installed.\n"
        "        Run:  pip install requests\n"
    )

# ── ANSI colours ───────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"

def clr(text: str, colour: str) -> str:
    return f"{colour}{text}{RESET}"

# ── Constants ──────────────────────────────────────────────────────────────────
LOG_FILE    = Path(__file__).parent / "university_access.log"
ENDPOINT    = "/api/logs"
LINE_DELAY  = 0.5   # seconds between each POST (overridable via --delay)

# ── Core injector ──────────────────────────────────────────────────────────────
def inject(base_url: str, delay: float) -> None:
    # ── 1. Locate the log file ─────────────────────────────────────────────────
    if not LOG_FILE.exists():
        print(clr(
            f"\n[FILE NOT FOUND]  '{LOG_FILE}' does not exist.\n"
            f"  Make sure 'university_access.log' is in the same directory\n"
            f"  as this script ({LOG_FILE.parent}) and try again.\n",
            RED,
        ))
        sys.exit(1)

    lines = [ln.rstrip("\n") for ln in LOG_FILE.read_text(encoding="utf-8").splitlines()
             if ln.strip()]   # skip blank lines

    total = len(lines)
    url   = f"{base_url}{ENDPOINT}"

    # ── Banner ─────────────────────────────────────────────────────────────────
    print(clr("\n╔══════════════════════════════════════════════════════════╗", CYAN + BOLD))
    print(clr( "║        UniGuard SIEM — File Injector                     ║", CYAN + BOLD))
    print(clr( "╚══════════════════════════════════════════════════════════╝\n", CYAN + BOLD))
    print(f"  {clr('Log file :', DIM)}  {LOG_FILE}")
    print(f"  {clr('Target   :', DIM)}  {clr(url, YELLOW)}")
    print(f"  {clr('Lines    :', DIM)}  {total}")
    print(f"  {clr('Delay    :', DIM)}  {delay}s per line")
    print(clr("\n  Starting stream — press Ctrl+C to abort.\n", DIM))
    print(f"  {'LINE':<6}  {'STATUS':<10}  RAW LOG ENTRY")
    print(f"  {'────':<6}  {'──────':<10}  {'─' * 55}")

    # ── 2. Iterate lines ───────────────────────────────────────────────────────
    sent = skipped = errors = 0

    for idx, raw in enumerate(lines, start=1):
        # Print the raw line to console first
        preview = raw if len(raw) <= 80 else raw[:77] + "..."
        print(f"  {clr(str(idx), CYAN):<14}  {clr('sending…', DIM):<18}  {preview}")

        # ── 3. HTTP POST ───────────────────────────────────────────────────────
        try:
            response = requests.post(
                url,
                json={"raw": raw},
                timeout=5,
            )

            if response.status_code == 201:
                data    = response.json()
                status  = data.get("parsed", {}).get("status", "?").upper()
                alert   = data.get("alert", False)

                colour  = RED if status == "FAIL" else GREEN
                a_tag   = clr("  ⚠  ALERT TRIGGERED", RED + BOLD) if alert else ""

                # Overwrite the "sending…" line with the result
                print(f"\033[1A\033[2K  {clr(str(idx), CYAN):<14}  "
                      f"{clr(status, colour):<18}  {preview}{a_tag}")
                sent += 1

            elif response.status_code == 422:
                print(f"\033[1A\033[2K  {clr(str(idx), CYAN):<14}  "
                      f"{clr('SKIPPED', YELLOW):<18}  {preview}"
                      f"  {clr('(unrecognised format)', DIM)}")
                skipped += 1

            else:
                print(f"\033[1A\033[2K  {clr(str(idx), CYAN):<14}  "
                      f"{clr('HTTP ' + str(response.status_code), RED):<18}  {preview}")
                errors += 1

        except requests.exceptions.ConnectionError:
            # ── 4. Server offline error ────────────────────────────────────────
            print(f"\033[1A\033[2K  {clr(str(idx), CYAN):<14}  "
                  f"{clr('CONN ERR', RED):<18}  {preview}")
            print(clr(
                f"\n[SERVER OFFLINE]  Could not connect to {url}\n"
                f"  → Make sure the UniGuard SIEM server is running:\n"
                f"        python app.py\n"
                f"  → Then re-run this script.\n",
                RED,
            ))
            sys.exit(1)

        except requests.exceptions.Timeout:
            print(f"\033[1A\033[2K  {clr(str(idx), CYAN):<14}  "
                  f"{clr('TIMEOUT', YELLOW):<18}  {preview}")
            errors += 1

        except Exception as exc:
            print(f"\033[1A\033[2K  {clr(str(idx), CYAN):<14}  "
                  f"{clr('ERROR', RED):<18}  {preview}  ({exc})")
            errors += 1

        # ── 3. Delay before next line ──────────────────────────────────────────
        if idx < total:
            try:
                time.sleep(delay)
            except KeyboardInterrupt:
                print(clr("\n\n  ↩  Aborted by user.\n", DIM))
                _print_summary(sent, skipped, errors, total)
                sys.exit(0)

    # ── Summary ────────────────────────────────────────────────────────────────
    _print_summary(sent, skipped, errors, total)


def _print_summary(sent: int, skipped: int, errors: int, total: int) -> None:
    print(clr("\n  ── Injection Summary ──────────────────────────────────", CYAN))
    print(f"  {clr('✓ Sent successfully :', GREEN)}  {sent} / {total}")
    if skipped:
        print(f"  {clr('⚠ Skipped (bad fmt) :', YELLOW)}  {skipped}")
    if errors:
        print(f"  {clr('✗ Errors            :', RED)}  {errors}")
    print(clr("  ────────────────────────────────────────────────────\n", CYAN))


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="UniGuard SIEM — streams university_access.log to /api/logs",
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:5000",
        help="Base URL of the running UniGuard SIEM server (default: http://127.0.0.1:5000)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=LINE_DELAY,
        help=f"Seconds to wait between each POST (default: {LINE_DELAY})",
    )
    args = parser.parse_args()

    inject(base_url=args.url.rstrip("/"), delay=args.delay)
