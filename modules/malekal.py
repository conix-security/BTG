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

from BTG import BTG
from lib.io import display
from requests import get
from re import findall
import config
import os
from platform import system
if system() != "Windows":
    import requests_cache 
    requests_cache.install_cache('%sBTG'%config.sqlite_path)

class Malekal:
    """
        This module allow you to search IOC in Malekal website (HTTP Requests)
        or local directory specified in BTG configuration file.
    """
    def __init__(self, ioc, type):
        if config.malekal_enabled:
            self.module_name = __name__.split(".")[1]
            if config.malekal_local and not config.malekal_remote:
                self.types = ["MD5"]
            else:
                self.types = [
                    "MD5", "SHA1", "SHA256", "SHA512", "URL",
                    "IPv4", "IPv6", "domain"
                ]
            self.search_method = "Online"
            self.description = "Search IOC in malekal database"
            self.author = "Conix"
            self.creation_date = "13-09-2016"
            self.type = type
            self.ioc = ioc
            if type in self.types:
                self.search()

    def search(self):
        display(self.module_name, self.ioc, "INFO", "Searching...")
        if config.malekal_local:
            self.localSearch()
        if config.malekal_remote and BTG.allowedToSearch(self.search_method):
            self.remoteSearch()

    def remoteSearch(self):
        """
            Search IOC with HTTP request
        """
        display("%s_remote"%self.module_name, self.ioc, "INFO", string="Browsing in remote http")
        url = "http://malwaredb.malekal.com/index.php?"
        if self.type in ["MD5", "SHA1", "SHA256", "SHA512"]:
            base = "hash="
        elif self.type in ["URL", "domain"]:
            base = "url="
        elif self.type in ["IPv4",  "IPv6"]:
            base = "domaine="
        try:
            page = get(
                "%s%s%s"%(url, base, self.ioc), 
                headers=config.user_agent,
                proxies=config.proxy_host,
                timeout=config.requests_timeout
            ).text
            if len(findall("hash=([a-z0-9]{32})\"", page)) > 1:
                display("%s_remote"%self.module_name, self.ioc, "FOUND", "%s%s%s"%(
                    url, base,
                    self.ioc))
        except:
            display("%s_remote"%self.module_name, self.ioc, "INFO", "MalekalTimeout")
            

    def localSearch(self):
        """ Search in local directory """
        display("%s_local"%self.module_name, string="Browsing in local directory")
        for root, dirs, files in os.walk(config.malekal_files_path):
            path = root.split('/')
            folder = os.path.basename(root)
            for file in files:
                if file == self.ioc:
                    display(
                        "%s_local"%self.module_name, self.ioc, "FOUND", "%s%s/%s"%(
                            config.malekal_files_path,
                            folder,
                            file
                        )
                    )
        
