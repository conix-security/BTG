#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2017 Conix Cybersecurity
# Copyright (c) 2017 Alexandra Toussaint
# Copyright (c) 2017 Robin Marsollier
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

import json
from platform import system

from requests import get

from lib.config_parser import Config
from lib.io import module as mod

cfg = Config.get_instance()
if system() != "Windows":
    import requests_cache

    requests_cache.install_cache('%sBTG' % cfg["sqlite_path"])


class Cuckoosandbox:
    """
        This module allow you to search IOC in CuckooSandbox database
    """

    def __init__(self, ioc, type, config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        self.types = [
            "MD5", "SHA256"
        ]
        self.search_method = "Onpremises"
        self.description = "Search IOC in CuckooSandbox database"
        self.author = "Conix"
        self.creation_date = "02-03-2017"
        self.type = type
        self.ioc = ioc
        if type in self.types and mod.allowedToSearch(self.search_method):
            length = len(self.config['cuckoosandbox_api_url'])
            if  length != len(self.config['cuckoosandbox_web_url']) and length <= 0:
                mod.display(self.module_name,
                            message_type="ERROR",
                            string="Cuckoosandbox fields in config.ini are missfilled, checkout commentaries.")
                return

            for indice in range(len(self.config['cuckoosandbox_api_url'])):
                api_url = self.config['cuckoosandbox_api_url'][indice]
                web_url = self.config['cuckoosandbox_web_url'][indice]
                self.search(api_url, web_url)
        else:
            mod.display(self.module_name, "", "INFO", "Cuckoosandbox module not activated")

    def search(self, api_url, web_url):
        mod.display(self.module_name, "", "INFO", "Searching...")
        if ("cuckoosandbox_api_url" in self.config and
            "user_agent" in self.config and
            "proxy_host" in self.config and
            "requests_timeout" in self.config):

            if self.type in ["MD5"]:
                url = "%s/files/view/md5/%s" % (api_url, self.ioc)
            elif self.type in ["SHA256"]:
                url = "%s/files/view/sha256/%s" % (api_url, self.ioc)
            try:
                page = get(
                    url,
                    headers=self.config["user_agent"],
                    proxies=self.config["proxy_host"],
                    timeout=self.config["requests_timeout"]
                )
            except:
                mod.display(self.module_name,
                            message_type="ERROR",
                            string="Unable to contact CuckooSandbox API")
                return
            if page.status_code == 200:
                if "Error: 404 Not Found" not in page.text and "File not found" not in page.text:
                    id_analysis = json.loads(page.text)["sample"]["id"]
                    if "cuckoosandbox_web_url" in self.config:
                        mod.display("%s_remote" % self.module_name,
                                    self.ioc,
                                    "FOUND",
                                    "%s/view/%s" % (web_url, id_analysis))
                    else:
                        mod.display(self.module_name,
                                    message_type="ERROR",
                                    string="Check if you have cuckoosandbox_web_url in config.ini")
        else:
            mod.display(self.module_name,
                        message_type="ERROR",
                        string=("Check if you have cuckoosandbox_api_url,user_agent,proxy_host and"
                                "requests_timeout field in config.ini"))
