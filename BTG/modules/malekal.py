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

import os
from platform import system
from re import findall
import json

from BTG.lib.config_parser import Config
from BTG.lib.io import module as mod
from BTG.lib.async_http import store_request

cfg = Config.get_instance()
if system() != "Windows":
    import requests_cache
    requests_cache.install_cache('%sBTG' % cfg["sqlite_path"])


class Malekal:
    """
        This module allow you to search IOC in Malekal website (HTTP Requests)
        or local directory specified in BTG configuration file.
    """
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        if "malekal_local" in self.config and "malekal_remote" in self.config:
            if self.config["malekal_local"] \
               and not self.config["malekal_remote"]:
                self.types = ["MD5"]
            else:
                self.types = [
                    "MD5", "SHA1", "SHA256", "SHA512", "URL",
                    "IPv4", "IPv6", "domain"
                ]
        else:
            mod.display(self.module_name,
                        self.ioc,
                        message_type="ERROR",
                        string=("Check if you have malekal_local or malekal_remote"
                                "fields in btg.cfg "))
            return None
        self.search_method = "Online"
        self.description = "Search IOC in malekal database"
        self.author = "Conix"
        self.creation_date = "13-09-2016"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "GET"
        self.headers = self.config["user_agent"]
        self.proxy = self.config["proxy_host"]

        if type in self.types and mod.allowedToSearch(self.search_method):
            self.search()
        else:
            mod.display(self.module_name,
                        self.ioc,
                        "INFO",
                        "Malekal module not activated")

    def search(self):
        mod.display(self.module_name, "", "INFO", "Searching...")
        if "malekal_local" in self.config:
            if self.config["malekal_local"]:
                self.localSearch()
        if "malekal_remote" in self.config:
            if self.config["malekal_remote"]:
                self.remoteSearch()

    def remoteSearch(self):
        """
            Search IOC with HTTP request
        """
        mod.display("%s_remote" % self.module_name,
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
        self.url = url+base+self.ioc

        request = {'url': self.url,
                   'headers': self.headers,
                   'module': self.module_name,
                   'ioc': self.ioc,
                   'verbose': self.verbose,
                   'proxy': self.proxy
                   }

        json_request = json.dumps(request)
        store_request(self.queues, json_request)

    def localSearch(self):
        """ Search in local directory """
        mod.display("%s_local" % self.module_name,
                    string="Browsing in local directory")
        if "malekal_files_path" in self.config:
            for root, dirs, files in os.walk(self.config["malekal_files_path"]):
                folder = os.path.basename(root)
                for file in files:
                    if file == self.ioc:
                        mod.display("%s_local" % self.module_name,
                                    self.ioc,
                                    "FOUND",
                                    "%s%s/%s" % (self.config["malekal_files_path"],
                                                 folder,
                                                 file))
                        return None
            mod.display("%s_local" % self.module_name,
                        self.ioc,
                        message_type="NOT_FOUND",
                        string="Nothing found in Malekal_local")
            return None
        else:
            mod.display("%s_local" % self.module_name,
                        self.ioc,
                        "ERROR",
                        "Check if you have malekal_files_path field in btg.cfg ")
            return None


def response_handler(response_text, response_status, module,
                     ioc, server_id=None):
    if response_status == 200:
        matches = findall("hash=([a-z0-9]{32})\"", response_text)
        if len(matches) >= 1:
            mod.display("%s_remote" % module,
                        ioc,
                        "FOUND",
                        "http://malwaredb.malekal.com/index.php?hash="+matches[0])
            return None
        else:
            mod.display("%s_remote" % module,
                        ioc,
                        "NOT_FOUND",
                        "Nothing found in Malekal_remote")
    else:
        mod.display("%s_remote" % module,
                    ioc,
                    "ERROR",
                    "Malekal connection status : %d" % (response_status))
