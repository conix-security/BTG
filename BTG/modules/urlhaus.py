#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2018 Tanguy Becam
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

import requests
import json
from lib.io import module as mod
from lib.cache import Cache
from random import choice, randint
import time
import csv

class urlhaus():
    """
        This module performs a Safe Browsing Lookup to Google API
    """
    def __init__(self, ioc, type, config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        self.types = ["URL", "domain"]
        self.search_method = "Online"
        self.description = "Search IOC in urlhause database"
        self.author = "Conix"
        self.creation_date = "31-05-2018"
        self.type = type
        self.ioc = ioc

        if type in self.types and mod.allowedToSearch(self.search_method):
            self.search()
        else:
            mod.display(self.module_name, "", "INFO", "URLhause module not activated")
            return None

    def search(self):
        mod.display(self.module_name, "", "INFO", "Search in URLhause ...")

        url = "https://urlhaus.abuse.ch/downloads/"
        paths = [
            "csv"
        ]
        content = Cache(self.module_name, url, paths[0], self.search_method).content
        # find should be faster then a simple for loop research
        if content.find(self.ioc) == -1:
            mod.display(self.module_name,
                        self.ioc,
                        "INFO",
                        "Nothing found in URLhause")
            return None
        else:
            try:
                reader = csv.reader(content.split('\n'), delimiter=',')
            except:
                mod.display(self.module_name,
                            self.ioc,
                            "ERROR",
                            "Could not parse CSV feed")
                return None
            for row in reader :
                if self.ioc in row:
                    mod.display(self.module_name,
                                self.ioc,
                                "FOUND",
                                row[-1])
                    return None
