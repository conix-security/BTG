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
import json
import config
from platform import system
if system() != "Windows":
    import requests_cache 
    requests_cache.install_cache('%sBTG'%config.sqlite_path)

class Cuckoosandbox:
    """
        This module allow you to search IOC in CuckooSandbox database
    """
    def __init__(self, ioc, type):
        if config.cuckoosandbox_enabled:
            self.module_name = __name__.split(".")[1]
            self.types = [
                "MD5", "SHA256"
            ]
            self.search_method = "Online"
            self.description = "Search IOC in CuckooSandbox database"
            self.author = "Conix"
            self.creation_date = "02-03-2017"
            self.type = type
            self.ioc = ioc
            if type in self.types:
                self.search()

    def search(self):
        display(self.module_name, self.ioc, "INFO", "Searching...")
        if BTG.allowedToSearch(self.search_method):
	        if self.type in ["MD5"]:
	            url = "%s/files/view/md5/%s"%(config.cuckoosandbox_API_url, self.ioc)
	        elif self.type in ["SHA256"]:
	            url = "%s/files/view/sha256/%s"%(config.cuckoosandbox_API_url, self.ioc)
	        page = get(
	            url, 
	            headers=config.user_agent,
	            proxies=config.proxy_host,
	            timeout=config.requests_timeout
	        ).text
	        if not "Error: 404 Not Found" in page:
	        	id_analysis = json.loads(page)["sample"]["id"]
	        	display("%s_remote"%self.module_name, self.ioc, "FOUND", "%s/view/%s"%(config.cuckoosandbox_WEB_url, id_analysis))
	        #except:
	        #    display("%s"%self.module_name, self.ioc, "INFO", "MalekalTimeout")
	           
