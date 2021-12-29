#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This file implements a "packet printer" (a tool to print packet).
"""

###################
#    This file implements a "packet printer".
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

__version__ = "1.0.3"
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

__all__ = ["PacketPrinter"]

from scapy.all import hexdump, raw, ls, packet


class PacketPrinter:

    """
    This class prints packets in different formats.
    """

    def __init__(
        self,
        hexa: bool = True,
        summary: bool = False,
        details1: bool = False,
        details2: bool = False,
        python: bool = False,
        raw_: bool = False,
        info: bool = False,
    ):
        self.functions = []

        if hexa:
            self.functions.append(hexdump)
        if summary:
            self.functions.append(self.print_summary)
        if details1:
            self.functions.append(packet.Packet.show)
        if details2:
            self.functions.append(packet.Packet.show2)
        if python:
            self.functions.append(self.print_command)
        if raw_:
            self.functions.append(self.print_raw)
        if info:
            self.functions.append(ls)

    def print_command(self, packet: packet.Packet) -> None:

        """
        This function prints the command to build the packet with scapy.
        """

        print(packet.command())

    def print_summary(self, packet: packet.Packet) -> None:

        """
        This function prints the summary of the packet
        (protocol, source IP, destination IP).
        """

        print(packet.summary())

    def print_raw(self, packet: packet.Packet) -> None:

        """
        This function prints the raw packet.
        """

        print(raw(packet))

    def print(self, packet: packet.Packet) -> None:

        """
        This function calls generic packet printing functions.
        """

        for function in self.functions:
            function(packet)
