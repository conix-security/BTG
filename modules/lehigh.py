#!/usr/bin/python
# -*- coding: utf-8 -*-
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


import config
from lib.cache import Cache
from lib.io import display
from re import findall

class Lehigh:
    def __init__(self, ioc, type):
        if config.lehigh_enabled:
            self.module_name = __name__.split(".")[1]
            self.types = ["domain"]
            self.search_method = "Online"
            self.description = "Search domain in Lehigh feeds"
            self.author = "Conix"
            self.creation_date = "15-09-2016"
            self.type = type
            self.ioc = ioc
            if type in self.types:
                self.search()

    def search(self):
        display(self.module_name, self.ioc, "INFO", "Searching...")
        url = "http://malwaredomains.lehigh.edu/files/"
        paths = [
            "domains.txt"
        ]
        for path in paths:
            content = Cache(self.module_name, url, path, self.search_method).content
            for line in content.split("\n"):
                if line and line[0] != '#':
                    base = line.split("\t\t")[1]
                    if self.ioc == base.split("\t")[0]:
                        display(self.module_name, self.ioc, "FOUND", "[%s] %s%s"%(base.split("\t")[1], url, path))

