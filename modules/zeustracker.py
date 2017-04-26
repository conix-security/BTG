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

from lib.cache import Cache
from lib.io import display
from lib.argument_parse import parse
import validators

class Zeustracker:
    def __init__(self, ioc, type, config):
        self.config = config
        if self.config["zeustracker_enabled"]:
            self.module_name = __name__.split(".")[1]
            self.types = ["domain", "IPv4", "URL"]
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
        url = "https://zeustracker.abuse.ch/"
        paths = [
            "blocklist.php?download=baddomains",
            "blocklist.php?download=ipblocklist",
            "blocklist.php?download=compromised"
        ]
        for path in paths:
            if self.type == "URL":
                try:
                    self.ioc = self.ioc.split("://")[1]
                except:
                    pass
            content = Cache(self.module_name, url, path, self.search_method).content
            for line in content.split("\n"):
                if path.split("=")[1] == "compromised":
                    if self.type == "URL":
                        if self.ioc == line:
                            display(self.module_name, self.ioc, "FOUND", "%s%s"%(url, path))
                            return
                    else:
                        line = line.split("/")[0]
                        try:
                            line = line.split(":")[0]
                        except:
                            pass
                if self.type == "domain" and parse.is_valid_domain(line.strip()):
                    if line.strip() == self.ioc:
                        display(self.module_name, self.ioc, "FOUND", "%s%s"%(url, path))
                        return
                elif self.type == "IPv4" and validators.ipv4(line.strip()):
                    if line.strip() == self.ioc:
                        display(self.module_name, self.ioc, "FOUND", "%s%s"%(url, path))
                        return
