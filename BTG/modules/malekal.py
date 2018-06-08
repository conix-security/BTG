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

import os
from platform import system
from re import findall

from requests import get

from lib.config_parser import Config
from lib.io import module as mod

cfg = Config.get_instance()
if system() != "Windows":
    import requests_cache
    requests_cache.install_cache('%sBTG'%cfg["sqlite_path"])


class Malekal:
    """
        This module allow you to search IOC in Malekal website (HTTP Requests)
        or local directory specified in BTG configuration file.
    """
    def __init__(self, ioc, type, config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        if "malekal_local" in self.config and "malekal_remote" in self.config:
            if self.config["malekal_local"] and not self.config["malekal_remote"]:
                self.types = ["MD5"]
            else:
                self.types = [
                    "MD5", "SHA1", "SHA256", "SHA512", "URL",
                    "IPv4", "IPv6", "domain"
                ]
        else:
            mod.display(self.module_name,
                        message_type="ERROR",
                        string=("Check if you have malekal_local and malekal_remote"
                                "fields in config.ini "))
        self.search_method = "Online"
        self.description = "Search IOC in malekal database"
        self.author = "Conix"
        self.creation_date = "13-09-2016"
        self.type = type
        self.ioc = ioc
        if type in self.types and mod.allowedToSearch(self.search_method):
            self.search()
        else:
            mod.display(self.module_name, "", "INFO", "Malekal module not activated")

    def search(self):
        mod.display(self.module_name, "", "INFO", "Searching...")
        if "malekal_local" in self.config:
            if self.config["malekal_local"]:
                self.localSearch()
        if "malekal_remote" in self.config:
            if self.config["malekal_remote"] and mod.allowedToSearch(self.search_method):
                self.remoteSearch()

    def remoteSearch(self):
        """
            Search IOC with HTTP request
        """
        mod.display("%s_remote"%self.module_name,
                    self.ioc,
                    "INFO",
                    string="Browsing in remote http")
        url = "http://malwaredb.malekal.com/index.php?"
        if self.type in ["MD5", "SHA1", "SHA256", "SHA512"]:
            base = "hash="
        elif self.type in ["URL", "domain"]:
            base = "url="
        elif self.type in ["IPv4", "IPv6"]:
            base = "domaine="
        try:
            if ("user_agent" in self.config and
                    "proxy_host" in self.config and
                    "requests_timeout" in self.config):
                page = get(
                    "%s%s%s"%(url, base, self.ioc),
                    headers=self.config["user_agent"],
                    proxies=self.config["proxy_host"],
                    timeout=self.config["requests_timeout"]
                ).text
                if len(findall("hash=([a-z0-9]{32})\"", page)) > 1:
                    mod.display("%s_remote"%self.module_name, self.ioc, "FOUND", "%s%s%s"%(
                        url, base,
                        self.ioc))
            else:
                mod.display(self.module_name,
                            message_type="ERROR",
                            string=("Check if you have user_agent, proxy_host and"
                                    "requests_timeout fields in config.ini "))
        except:
            mod.display("%s_remote"%self.module_name, self.ioc, "INFO", "MalekalTimeout")

    def localSearch(self):
        """ Search in local directory """
        mod.display("%s_local"%self.module_name, string="Browsing in local directory")
        if "malekal_files_path" in self.config:
            for root, dirs, files in os.walk(self.config["malekal_files_path"]):
                path = root.split('/')
                folder = os.path.basename(root)
                for file in files:
                    if file == self.ioc:
                        mod.display(
                            "%s_local"%self.module_name, self.ioc, "FOUND", "%s%s/%s"%(
                                self.config["malekal_files_path"],
                                folder,
                                file
                            )
                        )
        else:
            mod.display(self.module_name,
                        message_type="ERROR",
                        string="Check if you have malekal_files_path field in config.ini ")
