#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2017 Conix Cybersecurity
# Copyright (c) 2017 Alexandra Toussaint
# Copyright (c) 2017 Robin Marsollier
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

from lib.cache import Cache
from lib.io import module as mod


class Torips:
    def __init__(self, ioc, type, config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        self.types = ["IPv4"]
        self.search_method = "Online"
        self.description = "Search an IPv4 in tor exits nodes"
        self.author = "Conix"
        self.creation_date = "13-09-2016"
        self.type = type
        self.ioc = ioc
        if type in self.types and mod.allowedToSearch(self.search_method):
            self.search()
        else:
            mod.display(self.module_name, "", "INFO", "TorIps module not activated")

    def search(self):
        mod.display(self.module_name, "", "INFO", "Searching...")
        url = "http://torstatus.blutmagie.de/"
        paths = [
            "ip_list_all.php/Tor_ip_list_ALL.csv",
            "query_export.php/Tor_query_EXPORT.csv",
            "ip_list_exit.php/Tor_ip_list_EXIT.csv"
        ]
        for path in paths:
            if self.ioc in Cache(self.module_name, url, path, self.search_method).content:
                mod.display(self.module_name, self.ioc, "FOUND", "%s%s"%(url, path))
