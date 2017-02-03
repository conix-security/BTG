#!/usr/bin/python
# Copyright (c) 2016-2017 Conix Cybersecurity
#
# This file is part of BTG.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

import socket
from domaintools import Domain

class parse:
    """
        This function parse arguments type
    """
    def __init__(self, argument):
        self.argument = argument

    @classmethod
    def is_valid_ipv4_address(self, address):
        """
            Check if argument is a valid address IPv4
        """
        try:
            socket.inet_pton(socket.AF_INET, address)
        except AttributeError:  # no inet_pton here, sorry
            try:
                socket.inet_aton(address)
            except socket.error:
                return False
            return address.count('.') == 3
        except socket.error:  # not a valid address
            return False

        return True

    @classmethod
    def is_valid_ipv6_address(self, address):
        """
            Check if argument is a valid address IPv6
        """
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except socket.error:  # not a valid address
            return False
        return True

    @classmethod
    def is_valid_domain(self, domain):
        if domain and Domain(domain).valid:
            return True
        return False
