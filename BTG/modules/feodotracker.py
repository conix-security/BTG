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
from random import choice, randint
import time
import csv

class feodotracker():
    """
        This module performs a Safe Browsing Lookup to Google API
    """
    def __init__(self, ioc, type, config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        self.types = ["IPv4", "domain"]
        self.search_method = "Online"
        self.description = "Search IOC in FeodoTracker database"
        self.author = "Conix"
        self.creation_date = "31-05-2018"
        self.type = type
        self.ioc = ioc

        if type in self.types and mod.allowedToSearch(self.search_method):
            self.search()
        else:
            mod.display(self.module_name, "", "INFO", "FeodoTracker module not activated")
            return None

    # TODO
    # OFFLINE research from local .txt
    def search(self):
        mod.display(self.module_name, "", "INFO", "Search in FeodoTracker ...")

        if self.type == "IPv4":
            url = "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist"
        elif self.type == "domain":
            url = "https://feodotracker.abuse.ch/blocklist/?download=domainblocklist"
        else:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        "This IOC is of an unrecognized type: %s"%(self.type))

        response = requests.get(url)

        if response.status_code == 200:
            # find should be faster then a simple for loop research
            indice1 = response.text.find(self.ioc)
            if indice1 == -1:
                mod.display(self.module_name,
                            self.ioc,
                            "INFO",
                            "Nothing found in FeodoTracker")
                return None
            else:
                # To be sure
                # indice2 = response.text.find('\n', indice1)
                # print(response.text[indice1:indice2])
                
                url_reponse = "https://feodotracker.abuse.ch/host/"+self.ioc
                mod.display(self.module_name,
                            self.ioc,
                            "FOUND",
                            url_reponse)
                return None
        else:
            mod.display(self.module_name,
                        self.ioc,
                        message_type="ERROR",
                        string="FeodoTracker API connection status %d" % response.status_code)
            return None
