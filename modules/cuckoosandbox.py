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
import json
from platform import system
from config_parser import Config

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
            if "cuckoosandbox_api_url" in self.config and "user_agent" in self.config and "proxy_host" in self.config \
                    and "requests_timeout" in self.config:
                if self.type in ["MD5"]:
                    url = "%s/files/view/md5/%s" % (self.config["cuckoosandbox_api_url"], self.ioc)
                elif self.type in ["SHA256"]:
                    url = "%s/files/view/sha256/%s" % (self.config["cuckoosandbox_api_url"], self.ioc)
                page = get(
                    url,
                    headers=self.config["user_agent"],
                    proxies=self.config["proxy_host"],
                    timeout=self.config["requests_timeout"]
                ).text
                if not "Error: 404 Not Found" in page:
                    id_analysis = json.loads(page)["sample"]["id"]
                    if "cuckoosandbox_web_url" in self.config:
                        display("%s_remote" % self.module_name, self.ioc, "FOUND",
                                "%s/view/%s" % (self.config["cuckoosandbox_web_url"], id_analysis))
                    else:
                        display(self.module_name, message_type="ERROR",
                                string="Please check if you have cuckoosandbox_web_url field in config.ini")
            else:
                display(self.module_name, message_type="ERROR",
                        string="Please check if you have cuckoosandbox_api_url,user_agent,proxy_host and requests_timeout field in config.ini")

                # except:
                #    display("%s"%self.module_name, self.ioc, "INFO", "MalekalTimeout")
