# wifi-dos

Scapy implementations of two 802.11 denial-of-service techniques that
aren't well covered by the usual public tooling:

1. **Beacon DSSS Parameter Set DoS** -- spoof beacons that lie about the
   AP's channel, causing victim stations to retune off the real channel
   and lose connectivity.
2. **RTS/CTS NAV co-opting DoS** -- inject RTS or CTS control frames
   carrying a maximum Duration/ID value, forcing every station in earshot
   to defer transmission under the Network Allocation Vector.

Built as illustration code for SANS **SEC617: Wireless Penetration
Testing and Ethical Hacking** (course book pp. 104-111). The scripts
are intentionally short and self-contained so they read well in a
classroom setting.

The original course examples reference Joshua Wright's `file2air`,
which is hard to build on modern systems. These scripts re-implement
the same two attacks in scapy so the labs remain runnable on current
Linux distributions without out-of-tree tooling.

> Authorized lab use only. These tools degrade Wi-Fi connectivity for
> every station within radio range of the targeted AP or victim. Do not
> point them at networks you do not own or do not have written
> permission to test.

---

## How the attacks work

### Beacon DSSS Parameter Set DoS (SEC617 p. 104)

Stations rely on beacons for network information, including the AP's
current operating channel which is advertised in the DSSS Parameter Set
Information Element (Element ID 3) as a single byte. The attack
manipulates that value in spoofed beacon frames that otherwise match
the target AP's BSSID and SSID.

When a victim reads the spoofed beacon it trusts the channel value
inside it and either retunes off the AP's real channel or, if the
advertised channel is invalid (the SEC617 example uses channel **238**),
gets confused about the AP's state entirely. Either way the client
goes offline for several seconds while it re-scans. Repeating the
injection produces a sustained DoS.

Operational notes:

- The injection happens on the AP's **real** channel so victims hear
  it. The lie lives only inside the DSSS Parameter Set IE.
- Using an out-of-range channel (e.g. 238) avoids the chance that the
  victim cleanly retunes to a different valid AP. `beacon.py`'s
  `--channel` accepts any 1-byte value via the integer argument; pass
  a deliberately bogus value to mirror the SEC617 example.

### RTS/CTS NAV co-opting DoS (SEC617 pp. 106-110)

802.11 is half-duplex with CSMA/CA. To avoid the hidden-node problem,
where two stations that cannot hear each other transmit simultaneously
and collide, the standard provides the RTS/CTS exchange: the
transmitter sends an RTS specifying a duration, the recipient replies
with a CTS, and every station in earshot of either frame updates its
Network Allocation Vector (NAV) and refrains from transmitting until
the duration expires.

The attack abuses that cooperative mechanism. The 802.11 control-frame
Duration/ID field is 15 bits, so the maximum legal NAV is **32,767 µs**
(~32.7 ms). At that value, an attacker only needs **~31 packets per
second** (32.7 ms NAV * 31 packets ≈ 1 s) to keep neighboring stations
muted indefinitely. The reference pcaps in this repo and `RTS.py`'s
default actually use `0xFFFF` (65,535), which some chipsets accept; the
spec-conformant value `0x7FFF` works on more hardware. Override with
`-d/--duration` either way.

Two delivery modes:

- **RTS flood** -- send RTS from a spoofed client (TA) to the AP (RA).
  The AP politely replies with a CTS carrying the same big duration.
  Every station that hears the AP's CTS defers. This is the technique
  in SEC617 p. 110: the attacker can sit out of range of the actual
  victims (e.g. behind a directional antenna) and use the AP as an
  amplifier to push the NAV across the production WLAN.
- **CTS flood** -- send CTS directly to a victim STA (RA). Anyone in
  range of the CTS defers. No reply is generated. Quieter, more
  surgical, but limited to the attacker's own coverage.

Per SEC617 p. 109, "the attacker can co-opt other clients (CTS) --
extends range, effectiveness of attack." `RTS.py` realizes this with
the comma-separated `-c/--client` argument: pass multiple MACs and the
RA (CTS mode) or TA (RTS mode) is randomized per frame, broadening the
NAV hold without needing to physically move.

---

## Requirements

### Operating system

- Linux. `beacon_sweep.py` shells out to `iw` to hop channels and the
  RTS/CTS and beacon scripts depend on raw 802.11 injection through a
  monitor-mode interface, which is a Linux-only path in practice.
- Tested distributions: any modern Debian/Ubuntu/Kali release with
  `iw` and a working monitor-mode driver.

### Hardware

- A Wi-Fi adapter that supports monitor mode **and** frame injection.
  Common known-good options include Atheros AR9271 (TP-Link TL-WN722N
  v1), Ralink RT3070/RT5370, MediaTek MT7612U, Realtek RTL8812AU with
  the `aircrack-ng/rtl8812au` driver. Confirm with `aireplay-ng --test`
  before relying on it.
- 2.4 GHz coverage is the default. 5 GHz works for the per-AP scripts
  if your card+regdomain allow it; `beacon_sweep.py` ships with a 2.4
  GHz channel list by default, override with `--scan-channels`.

### Privileges

- Root (or `CAP_NET_RAW` + `CAP_NET_ADMIN`). All three scripts inject
  raw 802.11 frames; channel hopping in the sweep tool calls `iw`.

### Software

- Python 3.9 or newer.
- Scapy 2.5 or newer.
- `iw` (for `beacon_sweep.py` only).

---

## Installation

```bash
git clone <this-repo> wifi-dos
cd wifi-dos

python3 -m venv .venv
source .venv/bin/activate
pip install scapy
```

`iw` is in the `iw` package on Debian/Ubuntu/Kali:

```bash
sudo apt install iw
```

The scripts have no other Python dependencies. They import each other
in place, so keep them in the same directory.

---

## Putting the interface into monitor mode

Pick whichever workflow you prefer; the scripts only need a
monitor-mode interface name.

Using `airmon-ng` (creates a new interface like `wlan0mon`):

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

Using `iw` directly (reuses the original interface name):

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

Set the channel manually for the single-AP scripts:

```bash
sudo iw dev wlan0 set channel 6
```

`beacon_sweep.py` manages the channel itself.

---

## Scripts

### `beacon.py` -- single-AP DSSS Parameter Set DoS

Spoofs beacons for one specific BSSID/SSID advertising a bogus channel.

```text
usage: beacon.py [-h] -a AP -s SSID -i INTERFACE -c CHANNEL
                 [--no-privacy] [--interval INTERVAL] [--count COUNT] [-y]
```

| flag | meaning |
| --- | --- |
| `-a, --ap`        | target AP BSSID |
| `-s, --ssid`      | target SSID |
| `-i, --interface` | monitor-mode interface, tuned to the AP's **real** channel |
| `-c, --channel`   | the **lie** to inject into the DSSS Parameter Set IE (1-255). Values >14 are out of standard range and especially effective. The SEC617 example uses **238**. |
| `--no-privacy`    | advertise an open network (omit the privacy bit and RSN IE) |
| `--interval`      | inter-beacon interval, seconds (default 0.1) |
| `--count`         | total beacons to send (0 = run until Ctrl-C) |
| `-y, --yes`       | skip the interactive "Press Enter" prompt |

Examples:

```bash
# AP is really on channel 6; tell clients it moved to 11
sudo iw dev wlan0mon set channel 6
sudo python3 beacon.py -i wlan0mon -a 58:6d:8f:07:4e:8f -s voip -c 11

# SEC617 reference example: advertise the bogus channel 238
sudo python3 beacon.py -i wlan0mon -a 58:6d:8f:07:4e:8f -s voip -c 238
```

### `RTS.py` -- RTS/CTS NAV co-opting DoS

Floods RTS or CTS frames carrying `Duration/ID = 0xFFFF`. Accepts a
single MAC or a comma-separated list; when multiple MACs are supplied
the RA (CTS mode) or TA (RTS mode) is randomized per frame to broaden
the NAV hold.

```text
usage: RTS.py [-h] [-m {rts,cts}] [-a AP] -c CLIENT -i INTERFACE
              [-d DURATION] [--interval INTERVAL] [--count COUNT] [-y]
```

| flag | meaning |
| --- | --- |
| `-m, --mode`      | `rts` (default) or `cts` |
| `-a, --ap`        | AP MAC (RTS mode RA); ignored in CTS mode |
| `-c, --client`    | one MAC or a comma-separated list. RTS: spoofed TA(s). CTS: victim RA(s) |
| `-i, --interface` | monitor-mode interface on the target channel |
| `-d, --duration`  | Duration/ID in microseconds (default 65535; SEC617 canonical value is 32767) |
| `--interval`      | inter-frame interval, seconds (default 0.03 ≈ 33 pps, matches the "31 pps" rate from SEC617 p. 109) |
| `--count`         | total frames to send (0 = until Ctrl-C) |
| `-y, --yes`       | skip the prompt |

Examples:

```bash
# RTS flood: fake client RTSes the AP; the AP's CTS replies do the work
sudo python3 RTS.py -m rts -i wlan0mon \
    -a fe:2b:2a:a7:05:af -c 4c:8d:79:e3:40:c8

# CTS flood at one victim
sudo python3 RTS.py -m cts -i wlan0mon -c 4c:8d:79:e3:40:c8

# CTS flood at many victims (RA randomized per frame)
sudo python3 RTS.py -m cts -i wlan0mon \
    -c 4c:8d:79:e3:40:c8,aa:bb:cc:dd:ee:ff,11:22:33:44:55:66

# SEC617 canonical NAV value (0x7FFF = 32767 µs) at the documented 31 pps rate
sudo python3 RTS.py -m rts -i wlan0mon -d 32767 --interval 0.0323 \
    -a fe:2b:2a:a7:05:af -c 4c:8d:79:e3:40:c8
```

### `beacon_sweep.py` -- scan-and-sweep DSSS Parameter Set DoS

Scans for every visible AP across a set of channels, then continuously
spoofs beacons for each one with a falsified DSSS Parameter Set IE.

```text
usage: beacon_sweep.py [-h] -i INTERFACE [--scan-channels SCAN_CHANNELS]
                       [--dwell DWELL] [--spoof-channel SPOOF_CHANNEL]
                       [--burst BURST] [--interval INTERVAL]
                       [--include-ssid INCLUDE_SSID]
                       [--exclude-ssid EXCLUDE_SSID]
                       [--include-hidden] [-y]
```

| flag | meaning |
| --- | --- |
| `-i, --interface`   | monitor-mode interface |
| `--scan-channels`   | comma-separated channels to scan (default `1,6,11`) |
| `--dwell`           | seconds to sniff per channel during scan (default 4) |
| `--spoof-channel`   | force every spoofed beacon to advertise this channel; default is `real + 5` wrapped into 1-11 |
| `--burst`           | spoofed beacons per target per cycle (default 20) |
| `--interval`        | inter-beacon interval, seconds (default 0.02) |
| `--include-ssid`    | substring filter; repeatable; case-insensitive |
| `--exclude-ssid`    | substring blacklist; repeatable; case-insensitive |
| `--include-hidden`  | also attack APs with empty SSIDs |
| `-y, --yes`         | skip the confirmation prompt |

Phases:

1. Hop through `--scan-channels`, sniffing beacons each `--dwell`
   seconds and collecting unique `(BSSID, SSID, real_channel, privacy)`
   tuples.
2. Apply the `--include-ssid` / `--exclude-ssid` / `--include-hidden`
   filters, print the target list, prompt for confirmation.
3. Group targets by real channel, retune the interface once per
   channel, TX a `--burst` of spoofed beacons per AP. Cycle.

Examples:

```bash
# Hit only the lab SSIDs you care about
sudo python3 beacon_sweep.py -i wlan0mon \
    --include-ssid voip --include-ssid lab-

# Sweep everything but explicitly leave the corporate SSID alone
sudo python3 beacon_sweep.py -i wlan0mon --exclude-ssid corp
```

---

## Reference captures

Working pcaps captured against real hardware are checked in alongside
the scripts. Useful for offline frame inspection and for regression
testing the builders.

| file | what it is |
| --- | --- |
| `beacon.pcap`  | benign reference beacon captured from a real AP |
| `RTS.pcap`     | benign RTS captured from a real client |
| `RTS-mod.pcap` | the same RTS rewritten with `Duration/ID = 0xFFFF` |
| `CTS.pcap`     | benign CTS captured from a real client |
| `CTS-mod.pcap` | the same CTS rewritten with `Duration/ID = 0xFFFF` |

Open them in Wireshark or `tshark -V -r <file>` to see the exact bytes
the scripts emulate.

---

## Detection and mitigation

A few quick notes for the defensive side of the lab discussion:

- **Beacon DS-set DoS** -- a WIDS that tracks `(BSSID, channel)`
  bindings will flag a sudden beacon storm advertising a different
  channel for a known BSSID. Modern enterprise APs and Cisco/Aruba/
  Mist controllers detect this as "spoofed beacon" or "AP impersonation."
  Defenders can also watch for beacons received on a channel that
  doesn't match the DSSS IE -- the captured channel from the radiotap
  header should equal the advertised channel.
- **RTS/CTS NAV co-opt** -- Duration values near `0xFFFF` are very
  unusual for normal traffic. Sustained large Duration/ID values from a
  single RA/TA pair are a strong signal. 802.11w (Management Frame
  Protection) does not cover control frames; some vendors add NAV
  sanity checks in firmware that clamp absurd durations.

---

## Caveats

- Beacon DS-set attacks rely on the client trusting the DSSS Parameter
  Set IE. Some modern stacks cross-check the radiotap-reported channel
  against the advertised one and ignore mismatches.
- NAV co-opting is bounded by the receiver's enforcement of Duration/ID.
  Some chipsets clamp or ignore extreme values; results vary by victim.
- 5 GHz channels require `--scan-channels` overrides and a card+driver
  that supports injection on those channels.
- Channel hopping in `beacon_sweep.py` is best-effort; if `iw set
  channel` fails (regdomain, busy interface), the script exits with the
  underlying `iw` error.

---

## Files in this repo

```
beacon.py         single-AP DSSS Parameter Set DoS
RTS.py            RTS/CTS NAV co-opting DoS (single or multi-victim)
beacon_sweep.py   scan-and-sweep DSSS Parameter Set DoS
beacon.pcap       reference benign beacon
RTS.pcap          reference benign RTS
RTS-mod.pcap      RTS with Duration/ID = 0xFFFF (attack frame)
CTS.pcap          reference benign CTS
CTS-mod.pcap      CTS with Duration/ID = 0xFFFF (attack frame)
README.md         this file
```
