#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Hicham Megherbi
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

from BTG.lib.cache import Cache
from BTG.lib.io import module as mod

class Ransomwaretracker:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["domain", "URL", "IPv4", "IPv6"]
        self.search_method = "Online"
        self.description = "Search in ransomwaretracker feeds"
        self.author = "Hicham Megherbi"
        self.creation_date = "12-04-2017"
        self.type = type
        self.ioc = ioc
        if type in self.types and mod.allowedToSearch(self.search_method):
            self.search()
        else:
            mod.display(self.module_name, "", "INFO", "RansomwareTracker module not activated")

    def search(self):
        mod.display(self.module_name, "", "INFO", "Searching...")
        url = "https://ransomwaretracker.abuse.ch/feeds/"
        paths = [
            "csv"
        ]
        content = Cache(self.module_name, url, paths[0], self.search_method).content
        for line in content.split("\n"):
            try:
                if self.ioc in line:
                    mod.display(self.module_name,
                                self.ioc,
                                "FOUND",
                                "%s | %s%s"%(line.split(",")[2].replace('"', '', 2),
                                             url,
                                             paths[0]))
            except:
                pass
