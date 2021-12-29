#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This package prints and sniffs the packets.
"""

###################
#    This package prints and sniffs the packets.
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

__all__ = ["Sniffer", "PacketPrinter", "packets_analysis"]

from .PacketPrinter import PacketPrinter
from .Sniffer import Sniffer, main as packets_analysis

print(copyright)
