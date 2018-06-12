#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
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

import json

from BTG.lib.cache import Cache
from BTG.lib.io import module as mod


class Malshare():
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "SHA256", "SHA1"]
        self.search_method = "Online"
        self.description = "Search IOC in Malshare database"
        self.author = "Conix"
        self.creation_date = "12-04-2017"
        self.type = type
        self.ioc = ioc
        if type in self.types and mod.allowedToSearch(self.search_method):
            self.search()
        else:
            mod.display(self.module_name, "", "INFO", "Malshare module not activated")

    def search(self):
        mod.display(self.module_name, "", "INFO", "Searching...")
        url = "http://malshare.com/"
        if "malshare_api_key" in self.config:
            if self.config["malshare_api_key"]:
                paths = [
                    "api.php?api_key=%s&action=details&hash=%s" % (self.config["malshare_api_key"],
                                                                   self.ioc)
                ]
                for path in paths:
                    try:
                        content = json.loads(Cache(self.module_name,
                                                   url,
                                                   path,
                                                   self.search_method).content)

                        safe_urls = []
                        for malware_url in content["SOURCES"]:
                            safe_urls.append(malware_url.replace("http", "hxxp"))
                        mod.display(self.module_name,
                                    self.ioc,
                                    "FOUND",
                                    "%s | %s%s" % (safe_urls, url, path))
                        return
                    except:
                        pass
        else:
            mod.display(self.module_name,
                        message_type="ERROR",
                        string="You must have a malshare api key to use this module ")
