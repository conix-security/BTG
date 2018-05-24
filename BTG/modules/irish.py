#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Lancelot Bogard
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

from requests import get
import json

class Irish():
    def __init__(self, ioc, type, config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        self.types = ["MD5", "SHA256", "SHA1"]
        self.search_method = "Online"
        self.description = "Search IOC in IRIS-H. database"
        self.author = "Conix"
        self.creation_date = "01-12-2017"
        self.type = type
        self.ioc = ioc
        if type in self.types and mod.allowedToSearch(self.search_method):
            self.search()
        else:
            mod.display(self.module_name, "", "INFO", "IRIS-H module not activated")

    def search(self):
        mod.display(self.module_name, "", "INFO", "Searching...")
        request = get("https://iris-h.services/api/search?hash=%s"%self.ioc,
                        headers=self.config["user_agent"],
                        proxies=self.config["proxy_host"],
                        timeout=self.config["requests_timeout"])
        json_content = json.loads(request.text)
        if not "No report exists for %s hash"%self.ioc in json_content:
            mod.display(self.module_name,
                        self.ioc,
                        "FOUND",
                        "URL: https://iris-h.services/report/%s" % (self.ioc))
