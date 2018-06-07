#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Hicham Megherbi
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
from requests.auth import HTTPBasicAuth
from random import choice

from lib.io import module as mod


class Vxstream:
    def __init__(self, ioc, type, config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        self.types = ["MD5", "SHA1", "SHA256", "domain", "IPv4", "IPv6", "URL"]
        self.search_method = "Online"
        # Specifing user_agent to avoid the 403
        # self.headers = {'User-agent': 'Falcon Sandbox'}
        self.headers = {'User-agent': 'Falcon Sandbox',
                        'Content-type': 'application/x-www-form-urlencoded',
                        'accept': 'application/json'}
        self.description = "Search IOC in Hybrid Analysis"
        self.author = "Hicham Megherbi"
        self.creation_date = "20-10-2017"
        self.type = type
        self.ioc = ioc

        if type in self.types and mod.allowedToSearch(self.search_method):
            self.vxstream_api()
        else:
            mod.display(self.module_name, "", "INFO", "VXstream module not activated")

    def vxstream_api(self):
        """
        VXstream API Connection
        """
        if 'vxstream_api_keys' in self.config:
            self.headers["api-key"] = choice(self.config['vxstream_api_keys'])
        else:
            mod.display(self.module_name,
                        self.ioc,
                        message_type="ERROR",
                        string="Check if you have vxstream_api_keys_secret field in config.ini")
            return None

        if self.type in ["MD5", "SHA1", "SHA256"]:
            server = "https://www.hybrid-analysis.com/api/v2/search/hash"
            data = "hash=%s" % self.ioc
        else:
            server = "https://www.hybrid-analysis.com/api/v2/search/terms"
            if self.type in ["IPv4", "IPv6"]:
                data = "host="+self.ioc
            elif self.type == "URL":
                data = "url="+self.ioc
            else:
                data = "domain="+self.ioc

        respond = requests.post(server, headers=self.headers, data=data)

        if respond.status_code == 200:
            try:
                json_response = respond.json()
            except:
                mod.display(self.module_name,
                            self.ioc,
                            message_type="ERROR",
                            string="VxStream json_response was not readable.")
                return None

            if "count" in json_response and "search_terms" in json_response:
                if json_response["count"] > 0 :
                    verdict = json_response["result"][0]["verdict"]
                    threat_score = json_response["result"][0]["threat_score"]
                    type = json_response["search_terms"][0]["id"]
                    url = "https://www.hybrid-analysis.com/advanced-search-results?terms[%s]=%s" % (type, self.ioc)
                    mod.display(self.module_name,
                                self.ioc,
                                "FOUND",
                                "%s | %s/100 | %s" % (verdict, threat_score, url))
                return None

            if json_response:
                verdict = json_response[0]["verdict"]
                threat_score = json_response[0]["threat_score"]
                url = "https://www.hybrid-analysis.com/sample/"+self.ioc
                mod.display(self.module_name,
                            self.ioc,
                            "FOUND",
                            "%s | %s/100 | %s" % (verdict, threat_score, url))
                return None

        else:
            mod.display(self.module_name,
                        self.ioc,
                        message_type="ERROR",
                        string="VXstream API connection status %d" % respond.status_code)
            return None
