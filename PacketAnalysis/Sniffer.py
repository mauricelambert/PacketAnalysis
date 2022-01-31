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

>>> from scapy.all import conf
>>> sniffer = Sniffer(PacketPrinter())
>>> sniffer.start()
>>> sniffer.stop()
>>> sniffer = Sniffer(PacketPrinter(), "tcp port 80 or udp", "capture.pcap", None, conf.iface)
>>> sniffer = Sniffer(PacketPrinter(), filetoread="capture.pcap")

~# python3 Sniffer.py
[22/06/2022 02:53:11] WARNING  (30) {__main__ - Sniffer.py:302} Start the network sniffer on WIFI (IP: 172.16.10.55, MAC: ee:80:3d:0a:f9:2f).
<packets ...>
[22/06/2022 02:53:11] CRITICAL (50) {__main__ - Sniffer.py:312} Network traffic analysis is stopped.
~# python3 Sniffer.py -v -H -s -d -D -p -r -i -f "tcp port 80 or udp" -S capture.pcap -I 172.16.10.
[22/06/2022 02:53:11] DEBUG    (10) {__main__ - Sniffer.py:280} Logging is configured.
[22/06/2022 02:53:11] DEBUG    (10) {__main__ - Sniffer.py:291} PacketPrinter is created.
[22/06/2022 02:53:11] DEBUG    (10) {__main__ - Sniffer.py:165} Start network interface detection...
[22/06/2022 02:53:11] DEBUG    (10) {__main__ - Sniffer.py:181} Use network interface WIFI
[22/06/2022 02:53:11] DEBUG    (10) {__main__ - Sniffer.py:300} Sniffer is created.
[22/06/2022 02:53:11] WARNING  (30) {__main__ - Sniffer.py:302} Start the network sniffer on WIFI (IP: 172.16.10.55, MAC: ee:80:3d:0a:f9:2f).
[22/06/2022 02:53:11] DEBUG    (10) {__main__ - Sniffer.py:142} Start the scapy.sendrecv.sniff function...
<packets ...>
[22/06/2022 02:53:11] INFO     (20) {__main__ - Sniffer.py:192} Save the captured traffic.
[22/06/2022 02:53:11] CRITICAL (50) {__main__ - Sniffer.py:312} Network traffic analysis is stopped.
~# python3 Sniffer.py -R capture.pcap
[22/06/2022 02:53:11] WARNING  (30) {__main__ - Sniffer.py:302} Start the network sniffer on WIFI (IP: 172.16.10.55, MAC: ee:80:3d:0a:f9:2f).
<packets ...>
[22/06/2022 02:53:11] CRITICAL (50) {__main__ - Sniffer.py:312} Network traffic analysis is stopped.
"""

__version__ = "1.1.0"
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

from logging import StreamHandler, Formatter, Logger, getLogger, DEBUG, WARNING
from scapy.all import sniff, wrpcap, conf, IFACES
from argparse import ArgumentParser, Namespace
from scapy.interfaces import NetworkInterface
from collections.abc import Callable
from sys import exit, stdout
from typing import List

conf_iface: NetworkInterface = conf.iface


class ScapyArguments(ArgumentParser):

    """
    This class implements ArgumentsParser with
    interface argument and iface research.
    """

    interface_args: list = ["--interface", "-I"]
    interface_kwargs: dict = {
        "help": "Part of the IP, MAC or name of the interface",
    }

    def __init__(
        self,
        *args,
        interface_args=interface_args,
        interface_kwargs=interface_kwargs,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.interface_args = interface_args
        self.interface_kwargs = interface_kwargs
        self.add_argument(*interface_args, **interface_kwargs)

    def parse_args(
        self, args: List[str] = None, namespace: Namespace = None
    ) -> Namespace:

        """
        This function implements the iface
        research from interface arguments.
        """

        namespace: Namespace = ArgumentParser.parse_args(self, args, namespace)

        argument_name: str = max(self.interface_args, key=len)
        for char in self.prefix_chars:
            if char == argument_name[0]:
                argument_name = argument_name.lstrip(char)
                break

        interface = getattr(namespace, argument_name, None)

        if interface is not None:
            interface = interface.casefold()

            for temp_iface in IFACES.values():

                ip = temp_iface.ip
                mac = temp_iface.mac or ""
                name = temp_iface.name or ""
                network_name = temp_iface.network_name or ""

                mac = mac.casefold()
                name = name.casefold()
                network_name = network_name.casefold()

                if (
                    (ip and interface in ip)
                    or (mac and interface in mac)
                    or (name and interface in name)
                    or (network_name and interface in network_name)
                ):
                    namespace.iface = temp_iface
                    return namespace

        namespace.iface = conf_iface
        return namespace


def get_custom_logger() -> Logger:

    """
    This function create a custom logger.
    """

    logger = getLogger(__name__)  # default logger.level == 0

    formatter = Formatter(
        fmt=(
            "%(asctime)s%(levelname)-9s(%(levelno)s) "
            "{%(name)s - %(filename)s:%(lineno)d} %(message)s"
        ),
        datefmt="[%Y-%m-%d %H:%M:%S] ",
    )
    stream = StreamHandler(stream=stdout)
    stream.setFormatter(formatter)

    logger.addHandler(stream)

    return logger


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
        iface: NetworkInterface = None,
        **kwargs,
    ):
        self.packet_printer = packet_printer
        self.filetoread = filetoread
        self.savefile = savefile
        self.filter = filter_
        self.kwargs = kwargs
        self.iface = iface
        self.run = True

        self.is_running = lambda packet: not self.run

    def start(self) -> None:

        """
        This function starts the network sniffer.
        """

        logger_debug("Start the scapy.sendrecv.sniff function...")
        filetoread = self.filetoread

        if filetoread:
            self.packets = sniff(
                offline=filetoread,
                prn=self.packet_printer.print,
                **self.kwargs,
            )
        else:
            self.packets = sniff(
                filter=self.filter,
                stop_filter=self.is_running,
                prn=self.packet_printer.print,
                iface=self.iface,
                **self.kwargs,
            )

    def stop(self) -> None:

        """
        This function stops the sniffer and writes
        the pcap file to save the packets.
        """

        self.run = False
        savefile = self.savefile
        if savefile:
            logger_info("Save the captured traffic.")
            wrpcap(savefile, self.packets)


def parse() -> Namespace:

    """
    This function parses command line arguments.
    """

    parser = ScapyArguments(
        description="This program sniff the network connections."
    )
    add_argument = parser.add_argument
    add_argument(
        "--verbose",
        "-v",
        help="Mode verbose (print debug message)",
        action="store_true",
    )
    add_argument(
        "--no-hexa-printer",
        "-H",
        action="store_false",
        help="Do not print the hexadecimal packet",
        default=True,
    )
    add_argument(
        "--summary-printer",
        "-s",
        action="store_true",
        help="Print the packet summary",
    )
    add_argument(
        "--details-printer",
        "-d",
        action="store_true",
        help="Print packet details",
    )
    add_argument(
        "--details2-printer",
        "-D",
        action="store_true",
        help="Print packet details type 2",
    )
    add_argument(
        "--python-printer",
        "-p",
        action="store_true",
        help="Print the scapy command to build the package.",
    )
    add_argument(
        "--raw-printer", "-r", action="store_true", help="Print raw packet"
    )
    add_argument(
        "--info-printer",
        "-i",
        action="store_true",
        help="Print packet information",
    )
    add_argument("--filter", "-f", help="Scapy filter to select packets")
    add_argument("--savefilename", "-S", help="Pcap file to save packets")
    add_argument("--packet-file", "-R", help="Pcap file to read for analysis")

    return parser.parse_args()


def main() -> int:

    """
    This function starts the network sniffer from the command line.
    """

    arguments = parse()
    iface = arguments.iface

    logger.setLevel(DEBUG if arguments.verbose else WARNING)

    logger_debug("Logging is configured.")

    packet_printer = PacketPrinter(
        arguments.no_hexa_printer,
        arguments.summary_printer,
        arguments.details_printer,
        arguments.details2_printer,
        arguments.python_printer,
        arguments.raw_printer,
        arguments.info_printer,
    )
    logger_debug("PacketPrinter is created.")

    sniffer = Sniffer(
        packet_printer,
        filter_=arguments.filter,
        savefile=arguments.savefilename,
        filetoread=arguments.packet_file,
        iface=iface,
    )
    logger_debug("Sniffer is created.")

    logger_warning(
        f"Start the network sniffer on {iface.name}"
        f" (IP: {iface.ip}, MAC: {iface.mac})."
    )
    try:
        sniffer.start()
    except KeyboardInterrupt:
        logger_warning("KeyboardInterrupt: stop the network sniffer...")
    finally:
        sniffer.stop()
        logger_critical("Network traffic analysis is stopped.")

    return 0


logger: Logger = get_custom_logger()
logger_debug: Callable = logger.debug
logger_info: Callable = logger.info
logger_warning: Callable = logger.warning
logger_error: Callable = logger.error
logger_critical: Callable = logger.critical

if __name__ == "__main__":
    print(copyright)
    exit(main())
