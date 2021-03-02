#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This file implement Sniffer class. """

###################
#    This file implement Sniffer class.
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

try:
    from .PacketPrinter import PacketPrinter
except ImportError:
    from PacketPrinter import PacketPrinter

from scapy.all import sniff, wrpcap
from argparse import ArgumentParser

__all__ = ["Sniffer", "main"]


class Sniffer:

    """ This class sniff, filter and save packets. """

    def __init__(
        self,
        packet_printer,
        filter_: str = None,
        savefile: str = None,
        filetoread: str = None,
        iface: str = None,
    ):
        self.packet_printer = packet_printer
        self.savefile = savefile
        self.start = True
        self.filter = filter_
        self.filetoread = filetoread

        self.is_start = lambda packet: not self.start

        if self.filetoread:
            self.packets = sniff(offline=filetoread, prn=self.packet_printer.print)
        else:
            self.packets = sniff(
                filter=self.filter,
                stop_filter=self.is_start,
                prn=self.packet_printer.print,
                iface=iface,
            )

    def stop(self) -> None:

        """This function stop the sniffer and write
        the pcapfile to save packet."""

        self.start = False
        if self.savefile:
            wrpcap(self.savefile, self.packets)


def parse():

    """ This functions parse args. """

    parser = ArgumentParser()
    parser.add_argument(
        "--no-hexa-printer",
        "-H",
        action="store_false",
        help="Don't print hexa packet",
        default=True,
    )
    parser.add_argument(
        "--summary-printer", "-s", action="store_true", help="Print packet summary"
    )
    parser.add_argument(
        "--details-printer", "-d", action="store_true", help="Print packet details"
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
        help="Print packet scapy command",
    )
    parser.add_argument(
        "--raw-printer", "-r", action="store_true", help="Print packet raw"
    )
    parser.add_argument(
        "--info-printer", "-i", action="store_true", help="Print packet informations"
    )
    parser.add_argument(
        "--filter", "-f", help="Scapy filter to select packets.", default=None
    )
    parser.add_argument(
        "--savefilename", "-S", help="Pcap file to save packets.", default=None
    )
    parser.add_argument(
        "--packet-file", "-R", help="Pcap file to read for analysis.", default=None
    )
    parser.add_argument("--iface", "-I", help="Interface to sniff.", default=None)

    return parser.parse_args()


def main():

    """ This function launch the command line. """

    args = parse()

    packet_printer = PacketPrinter(
        args.no_hexa_printer,
        args.summary_printer,
        args.details_printer,
        args.details2_printer,
        args.python_printer,
        args.raw_printer,
        args.info_printer,
    )

    try:
        sniffer = Sniffer(
            packet_printer,
            filter_=args.filter,
            savefile=args.savefilename,
            filetoread=args.packet_file,
            iface=args.iface,
        )
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()