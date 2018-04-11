#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Tanguy Becam
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

class googleSB:
    def __init__(self, ioc, type, config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        self.types = ["MD5", "SHA1", "SHA256", "URL", "IPv4", "domain"]
        # googleSB run on a local database with a 30min refresh by default
        self.search_method = "Online"
        self.description = "Search IOC in GoogleSafeBrowsing database"
        self.author = "Tanguy Becam"
        self.creation_date = "11-04-2018"
        self.type = type
        self.ioc = ioc

        if type in self.types and mod.allowedToSearch(self.search_method):
            self.Search()
        else:
            mod.display(self.module_name, "", "INFO", "googleSB module not activated")

    def lookup_API(self):
        server = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="

        if 'googleSB_api_keys' in self.config:
            api_key = choice(self.config['googleSB_api_keys'])
        else:
            mod.display(self.module_name,
                            message_type="ERROR",
                            string="Check if you have googleSB_api_keys field in config.ini")


        respond = requests.post(

    # Is it needed ?
    # def update_API(self):
