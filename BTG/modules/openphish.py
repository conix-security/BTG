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

import validators
from BTG.lib.cache import Cache
from BTG.lib.io import module as mod


class Openphish:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["domain", "URL", "IPv4"]
        self.search_method = "Online"
        self.description = "Search domain in Openphish feeds"
        self.author = "Conix"
        self.creation_date = "15-09-2016"
        self.type = type
        self.ioc = ioc
        if mod.allowedToSearch(self.search_method):
            self.search()
        else:
            mod.display(self.module_name, "", "INFO", "OpenPhish module not activated")

    def search(self):
        mod.display(self.module_name, "", "INFO", "Searching...")
        url = "https://openphish.com/"
        paths = [
            "feed.txt"
        ]
        for path in paths:
            content = Cache(self.module_name, url, path, self.search_method).content
            for line in content.split("\n"):
                try:
                    midle = line.split("//")[-1].split("/")[0]
                except:
                    midle = None
                if self.type == "URL":
                    if self.ioc in line:
                        mod.display(self.module_name, self.ioc, "FOUND", "%s%s"%(url, path))
                        return None
                elif self.type == "IPv4" and validators.ipv4(midle):
                    if self.ioc == midle:
                        mod.display(self.module_name, self.ioc, "FOUND", "%s%s"%(url, path))
                        return None
                elif self.type == "domain" and validators.domain(midle):
                    if midle == self.ioc:
                        mod.display(self.module_name, self.ioc, "FOUND", "%s%s"%(url, path))
                        return None
        mod.display(self.module_name,
                    self.ioc,
                    "FOUND",
                    "Nothing found in openphish feeds")
