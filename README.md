# Packet

A network packet sniffer written in C on top of `libpcap`. It captures frames live off a
network interface and prints a decoded, human-readable breakdown of each protocol header.

Think of it as a small, readable tcpdump — built to make the layout of real network
protocols visible rather than to compete on features.

## What it decodes

| Layer | Protocols |
|---|---|
| Link | Ethernet, ARP |
| Network | IPv4, IPv6 |
| Transport | TCP, UDP, ICMP |

For each packet it reports the fields that matter at that layer — MAC and IP addresses,
ports, TCP flags and sequence numbers, TTL and hop limit, fragmentation flags, ICMP
type/code — and **validates the IPv4 header checksum** against a freshly computed one.

## Requirements

- `gcc` and `make`
- `libpcap` development headers
- Root (or `CAP_NET_RAW`) to capture — see [Running](#running)

```bash
sudo apt install libpcap-dev      # Debian / Ubuntu
sudo dnf install libpcap-devel    # Fedora / RHEL
```

## Building

```bash
make            # build ./main
make clean      # remove object files and the binary
```

## Running

Packet capture requires elevated privileges, so run it under `sudo`:

```bash
sudo ./main
```

It captures indefinitely; stop it with `Ctrl-C`.


## Example output

Captured from a live interface — a TCP SYN opening an HTTP connection:

```
dst MacAddress: 00:50:56:E1:AE:AE
Sender MacAddress: 00:0C:29:4B:E5:25
Type: IPv4
Protocol: TCP
version: 4
Version string: IPv4
header length: 20 bytes
Total Length: 60 bytes
ID: 1741
Fragmention: 16384
Dont Fragment: 1
More Fragment: 0
frag Offset: 0
TTL: 64
Checksum: 0x1991  OK
Destination Address: 172.66.147.243
Sender Address: 192.168.25.128
Src Port: 33076
Dst Port: 80
Seq: 1262516943
Ack: 0
header length: 40 bytes
Flags: SYN
Window: 64240
Checksum: 0x1a8d
===============================
```

An ARP request on the same network:

```
Type: ARP
Operation: Request
Sender: 192.168.25.133 (00:0C:29:55:75:12)
Target: 192.168.25.254 (00:00:00:00:00:00)
===============================
```

## How it is organised

The code is split into three layers, deliberately kept separate:

```
main.c                  Sets up the capture pipeline
headerFiles/            Header files
  Service/                Capture, logging, protocol constants, error type
  parsers/                One header per protocol
src/
  parsers/              Decode only — no output
  utils/                Capture, output, shared helpers
```

