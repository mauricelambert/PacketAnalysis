# PacketAnalysis

## Description
This package implement Packet Analysis with network sniffer or pcap file reader.

## Requirements
This package require :
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
PacketAnalysis
```

### Python3
```python
from PacketAnalysis import PacketPrinter, Sniffer
packet_printer = PacketPrinter()
sniffer = Sniffer(packet_printer)
```

## Links
 - [Github Page](https://github.com/mauricelambert/PacketAnalysis)
 - [Documentation PacketPrinter](https://mauricelambert.github.io/info/python/security/PacketAnalysis/PacketPrinter.html)
 - [Documentation Sniffer](https://mauricelambert.github.io/info/python/security/PacketAnalysis/Sniffer.html)
 - [Download as python executable](https://mauricelambert.github.io/info/python/security/PacketAnalysis.pyz)

## Licence
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).