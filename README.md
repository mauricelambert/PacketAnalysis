![PacketAnalysis logo](https://mauricelambert.github.io/info/python/security/PacketAnalysis_small.png "PacketAnalysis logo")

# PacketAnalysis

## Description

This package prints and sniffs the packets.

## Requirements

This package require:
 - python3
 - python3 Standard Library
 - Scapy

## Installation
```bash
pip install PacketAnalysis
```

## Examples

### Command lines

```bash
python3 -m PacketAnalysis
python3 -m PacketAnalysis.Sniffer
python3 PacketAnalysis.pyz
PacketAnalysis -h
PacketAnalysis --help
PacketAnalysis
PacketAnalysis -v -H -s -d -D -p -r -i -f "tcp port 80 or udp" -S capture.pcap -I 172.16.10.
PacketAnalysis -R capture.pcap
```

### Python3

```python
from PacketAnalysis import PacketPrinter, Sniffer

sniffer = Sniffer(PacketPrinter())
sniffer.start()
sniffer.stop()

sniffer = Sniffer(PacketPrinter(), "tcp port 80 or udp", "capture.pcap", None, "172.16.10.")

sniffer = Sniffer(PacketPrinter(), filetoread="capture.pcap")
```

## Links
 - [Github Page](https://github.com/mauricelambert/PacketAnalysis)
 - [Pypi](https://pypi.org/project/PacketAnalysis/)
 - [Documentation PacketPrinter](https://mauricelambert.github.io/info/python/security/PacketAnalysis/PacketPrinter.html)
 - [Documentation Sniffer](https://mauricelambert.github.io/info/python/security/PacketAnalysis/Sniffer.html)
 - [Download as python executable](https://mauricelambert.github.io/info/python/security/PacketAnalysis.pyz)

## Help

```text
usage: PacketAnalysis.pyz [-h] [--verbose] [--no-hexa-printer] [--summary-printer] [--details-printer] [--details2-printer] [--python-printer] [--raw-printer] [--info-printer] [--filter FILTER]
                          [--savefilename SAVEFILENAME] [--packet-file PACKET_FILE] [--iface IFACE]

optional arguments:
  -h, --help            show this help message and exit
  --verbose, -v         Mode verbose (print debug message)
  --no-hexa-printer, -H
                        Do not print the hexadecimal packet
  --summary-printer, -s
                        Print the packet summary
  --details-printer, -d
                        Print packet details
  --details2-printer, -D
                        Print packet details type 2
  --python-printer, -p  Print the scapy command to build the package.
  --raw-printer, -r     Print raw packet
  --info-printer, -i    Print packet information
  --filter FILTER, -f FILTER
                        Scapy filter to select packets
  --savefilename SAVEFILENAME, -S SAVEFILENAME
                        Pcap file to save packets
  --packet-file PACKET_FILE, -R PACKET_FILE
                        Pcap file to read for analysis
  --iface IFACE, -I IFACE
                        Part of the IP, MAC or name of the interface
```

## Licence
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).