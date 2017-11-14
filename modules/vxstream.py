#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Hicham Megherbi
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
        self.types = ["MD5", "SHA1", "SHA256", "domain", "IPv4", "IPv6"]
        self.search_method = "Online"
        self.description = "Search IOC in Hybride Analyses"
        self.author = "Hicham Megherbi"
        self.creation_date = "20-10-2017"
        self.type = type
        self.ioc = ioc

        if type in self.types and mod.allowedToSearch(self.search_method):
            self.Search()
        else:
            mod.display(self.module_name, "", "INFO", "VXstream module not activated")

    def vxstream_api(self):
        """
        VXstream API Connection
        """
        if self.type in ["MD5", "SHA1", "SHA256"]:
            server = "https://www.hybrid-analysis.com/api/scan/"
        if self.type in ["IPv4", "IPv6"]:
            server = "https://www.hybrid-analysis.com/api/search?query=host:"
        if self.type in ["domain"]:
            server = "https://www.hybrid-analysis.com/api/search?query=domain:"

        if 'vxstream_api_keys_secret' in self.config:
            api_key_secret = choice(self.config['vxstream_api_keys_secret'])
        else:
            mod.display(self.module_name,
                            message_type="ERROR",
                            string="Check if you have vxstream_api_keys_secret field in config.ini")

        respond = requests.get(server + self.ioc, headers=self.config['vxstream_user_agent'], verify=True, auth=HTTPBasicAuth(api_key_secret[0], api_key_secret[1]))
        if respond.status_code == 200:
            respond_json = respond.json()
            if respond_json["response_code"] == 0:
                return respond_json
            else:
                if respond_json["response_code"] == -1 and ("error" in respond_json["response"]):
                    mod.display(self.module_name,
                            message_type="ERROR",
                            string="%s" % respond_json["response"]["error"] )
                return None
        else:
            mod.display(self.module_name,
                        message_type="ERROR",
                        string="VXstream API connection status %d" % respond.status_code)
            return None

    def Search(self):
        mod.display(self.module_name, "", "INFO", "Search in VXstream ...")

        try:
            if "vxstream_api_keys_secret" in self.config:
                if self.type in self.types:
                        result_json = self.vxstream_api()
            else:
                mod.display(self.module_name,
                            message_type=":",
                            string="Please check if you have vxstream field in config.ini")

        except Exception as e:
            mod.display(self.module_name, self.ioc, "ERROR", e)
            return

        try:
            if result_json["response"]:
                if self.type in ["MD5", "SHA1", "SHA256"]:
                    result = result_json["response"][0]
                    if "classification_tags" in result and result["classification_tags"]:
                        tags = " Tags: %s |" % ",".join(result["classification_tags"])
                    else:
                        tags = ""
                    if "verdict" in result:
                        verdict = " %s |" % result["verdict"]
                    else:
                        verdict = ""
                    if "threatscore" in result:
                        threatscore = " Threatscore: %d/100 |" % result["threatscore"]
                    else:
                        threatscore =  ""
                    if "sha256" in result:
                        url = ' https://www.hybrid-analysis.com/sample/%s' % result["sha256"]
                    else:
                        url = ""
                    mod.display(self.module_name,
                                self.ioc,
                                "FOUND",
                                "%s%s%s%s" % (tags, verdict, threatscore, url))

                if self.type in ["domain", "IPv4", "IPv6"]:
                    result = result_json["response"]["result"]
                    nb_result = len(result)
                    if nb_result > 0:
                        if self.type in ["IPv4", "IPv6"]:
                            url = "https://www.hybrid-analysis.com/advanced-search-results?terms[host_with_port]=%s" % self.ioc
                        if self.type in ["domain"]:
                            url = "https://www.hybrid-analysis.com/advanced-search-results?terms[domain]=%s" % self.ioc
                        mod.display(self.module_name,
                                    self.ioc,
                                    "FOUND",
                                    "Results: %d | %s" % (nb_result, url))

        except:
            pass
