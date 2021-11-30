#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file implements a network sniffer.
#    Copyright (C) 2021  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This file implements a network sniffer.

>>> sniffer = Sniffer(PacketPrinter())
>>> sniffer.start()
>>> sniffer.stop()
>>> sniffer = Sniffer(PacketPrinter(), "tcp port 80 or udp", "capture.pcap", None, "172.16.10.")
>>> sniffer = Sniffer(PacketPrinter(), filetoread="capture.pcap")

~# python3 Sniffer.py
[22/06/2022 02:53:11 AM] WARNING  Start the network sniffer on WIFI (IP: 172.16.10.55, MAC: ee:80:3d:0a:f9:2f).
<packets ...>
[22/06/2022 02:53:11 AM] CRITICAL Network traffic analysis is stopped.
~# python3 Sniffer.py -v -H -s -d -D -p -r -i -f "tcp port 80 or udp" -S capture.pcap -I 172.16.10.
[22/06/2022 02:53:11 AM] DEBUG    Logging is configured.
[22/06/2022 02:53:11 AM] DEBUG    PacketPrinter is created.
[22/06/2022 02:53:11 AM] DEBUG    Start network interface detection...
[22/06/2022 02:53:11 AM] INFO     Interface argument match with (172.16.10.55 ee:80:3d:0a:f9:2f WIFI)
[22/06/2022 02:53:11 AM] DEBUG    Use network interface WIFI
[22/06/2022 02:53:11 AM] DEBUG    Sniffer is created.
[22/06/2022 02:53:11 AM] WARNING  Start the network sniffer on WIFI (IP: 172.16.10.55, MAC: ee:80:3d:0a:f9:2f).
[22/06/2022 02:53:11 AM] DEBUG    Start the scapy.sendrecv.sniff function...
<packets ...>
[22/06/2022 02:53:16 AM] INFO     Save the captured traffic.
[22/06/2022 02:53:16 AM] CRITICAL Network traffic analysis is stopped.
~# python3 Sniffer.py -R capture.pcap
[22/06/2022 02:53:11 AM] WARNING  Start the network sniffer on WIFI (IP: 172.16.10.55, MAC: ee:80:3d:0a:f9:2f).
<packets ...>
[22/06/2022 02:53:11 AM] CRITICAL Network traffic analysis is stopped.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This file implements a network sniffer.
"""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/PacketAnalysis"

copyright = """
PacketAnalysis  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["Sniffer", "main"]

try:
    from .PacketPrinter import PacketPrinter
except ImportError:
    from PacketPrinter import PacketPrinter

from scapy.all import sniff, wrpcap, conf, IFACES
from argparse import ArgumentParser, Namespace
import scapy.interfaces
import logging
import sys


class Sniffer:

    """
    This class sniffs, filters and saves packets.
    """

    def __init__(
        self,
        packet_printer: PacketPrinter,
        filter_: str = None,
        savefile: str = None,
        filetoread: str = None,
        iface: str = None,
        **kwargs,
    ):
        self.packet_printer = packet_printer
        self.savefile = savefile
        self.run = True
        self.filter = filter_
        self.filetoread = filetoread
        self.string_iface = iface
        self.iface = self.get_iface()
        self.kwargs = kwargs

        self.is_running = lambda packet: not self.run

    def start(self) -> None:

        """
        This function starts the network sniffer.
        """

        logging.debug("Start the scapy.sendrecv.sniff function...")

        if self.filetoread:
            self.packets = sniff(
                offline=self.filetoread, prn=self.packet_printer.print, **self.kwargs
            )
        else:
            self.packets = sniff(
                filter=self.filter,
                stop_filter=self.is_running,
                prn=self.packet_printer.print,
                iface=self.iface,
                **self.kwargs,
            )

    def get_iface(self) -> scapy.interfaces.NetworkInterface:

        """
        This function get a NetworkInterface from iface arguments
        (a string of IP or MAC address or interface name).
        """

        self.iface = conf.iface
        logging.debug("Start network interface detection...")

        if self.string_iface is not None:
            for iface_ in IFACES.values():
                if (
                    self.string_iface in iface_.ip
                    or self.string_iface in iface_.mac
                    or self.string_iface in iface_.network_name
                ):
                    logging.info(
                        "Interface argument match with "
                        f"({iface_.ip} {iface_.mac} {iface_.name})"
                    )
                    self.iface = iface_
                    break

        logging.debug(f"Use network interface {self.iface.name}")
        return self.iface

    def stop(self) -> None:

        """
        This function stops the sniffer and writes
        the pcap file to save the package.
        """

        self.run = False
        if self.savefile:
            logging.info("Save the captured traffic.")
            wrpcap(self.savefile, self.packets)


def parse() -> Namespace:

    """
    This function parses command line arguments.
    """

    parser = ArgumentParser()
    parser.add_argument(
        "--verbose",
        "-v",
        help="Mode verbose (print debug message)",
        action="store_true",
    )
    parser.add_argument(
        "--no-hexa-printer",
        "-H",
        action="store_false",
        help="Do not print the hexadecimal packet",
        default=True,
    )
    parser.add_argument(
        "--summary-printer",
        "-s",
        action="store_true",
        help="Print the packet summary",
    )
    parser.add_argument(
        "--details-printer",
        "-d",
        action="store_true",
        help="Print packet details",
    )
    parser.add_argument(
        "--details2-printer",
        "-D",
        action="store_true",
        help="Print packet details type 2",
    )
    parser.add_argument(
        "--python-printer",
        "-p",
        action="store_true",
        help="Print the scapy command to build the package.",
    )
    parser.add_argument(
        "--raw-printer", "-r", action="store_true", help="Print raw packet"
    )
    parser.add_argument(
        "--info-printer",
        "-i",
        action="store_true",
        help="Print packet information",
    )
    parser.add_argument(
        "--filter", "-f", help="Scapy filter to select packets"
    )
    parser.add_argument(
        "--savefilename", "-S", help="Pcap file to save packets"
    )
    parser.add_argument(
        "--packet-file", "-R", help="Pcap file to read for analysis"
    )
    parser.add_argument(
        "--iface", "-I", help="Part of the IP, MAC or name of the interface"
    )

    return parser.parse_args()


def main() -> None:

    """
    This function start the network
    sniffer from the command line.
    """

    arguments = parse()

    logging.basicConfig(
        level=logging.DEBUG if arguments.verbose else logging.WARNING,
        format="%(asctime)s%(levelname)-9s%(message)s",
        datefmt="[%m/%d/%Y %I:%M:%S %p] ",
    )

    logging.debug("Logging is configured.")

    packet_printer = PacketPrinter(
        arguments.no_hexa_printer,
        arguments.summary_printer,
        arguments.details_printer,
        arguments.details2_printer,
        arguments.python_printer,
        arguments.raw_printer,
        arguments.info_printer,
    )
    logging.debug("PacketPrinter is created.")

    sniffer = Sniffer(
        packet_printer,
        filter_=arguments.filter,
        savefile=arguments.savefilename,
        filetoread=arguments.packet_file,
        iface=arguments.iface,
    )
    logging.debug("Sniffer is created.")

    logging.warning(
        f"Start the network sniffer on {sniffer.iface.name}"
        f" (IP: {sniffer.iface.ip}, MAC: {sniffer.iface.mac})."
    )
    try:
        sniffer.start()
    except KeyboardInterrupt:
        logging.warning("KeyboardInterrupt: stop the network sniffer...")
    finally:
        sniffer.stop()
        logging.critical("Network traffic analysis is stopped.")


if __name__ == "__main__":
    main()
    sys.exit(0)
