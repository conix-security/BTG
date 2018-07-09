#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
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
import random

from BTG.lib.async_http import store_request
from BTG.lib.io import module as mod


class metadefender:
    """
        This module performs a Safe Browsing Lookup to Google API
    """
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "SHA1", "SHA256", "SHA512"]
        self.search_method = "Online"
        self.description = "Search IOC in MetaDefender"
        self.author = "Conix"
        self.creation_date = "13-04-2018"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "GET"
        self.headers = self.config["user_agent"]
        self.proxy = self.config["proxy_host"]

        self.Search()

    def Search(self):
        mod.display(self.module_name, "", "INFO", "Search in MetaDefender ...")

        try:
            if 'metadefender_api_keys' in self.config:
                api_key = random.Random(self.ioc).choice(self.config['metadefender_api_keys'])
                self.headers['apikey'] = api_key
            else:
                mod.display(self.module_name,
                            self.ioc,
                            message_type="ERROR",
                            string="Check if you have metadefender_api_keys field in btg.cfg")
                return None
        except:
            mod.display(self.module_name, self.ioc, "ERROR", "Please provide your MetaDefender key")
            return None

        # URL building
        self.url = "https://api.metadefender.com/v2/hash/"+self.ioc

        request = {'url': self.url,
                   'headers': self.headers,
                   'module': self.module_name,
                   'ioc': self.ioc,
                   'verbose': self.verbose,
                   'proxy': self.proxy
                   }

        json_request = json.dumps(request)
        store_request(self.queues, json_request)


def response_handler(response_text, response_status,
                     module, ioc, server_id=None):
    if response_status == 200:
        url_result = "https://www.metadefender.com/results#!/hash/"
        try:
            json_response = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        "ERROR",
                        "MetaDefender json_response was not readable.")
            return None
        if ioc in json_response:
            if json_response[ioc] == "Not Found":
                mod.display(module,
                            ioc,
                            "NOT_FOUND",
                            "Nothing found in MetaDefender")
        elif ioc.upper() in json_response:
            if json_response[ioc.upper()] == "Not Found":
                mod.display(module,
                            ioc,
                            "NOT_FOUND",
                            "Nothing found in MetaDefender")
        elif json_response['scan_results']['scan_all_result_a'] == "No Threat Detected":
            mod.display(module,
                        ioc,
                        "NOT_FOUND",
                        "Nothing found in MetaDefender database")
        elif json_response['scan_results']['scan_all_result_a'] == "Clear":
            mod.display(module,
                        ioc,
                        "FOUND",
                        url_result+json_response['data_id'])
        elif json_response['scan_results']['scan_all_result_a'] == "Infected" or json_response['scan_results']['scan_all_result_a'] == "Suspicious":
            mod.display(module,
                        ioc,
                        "FOUND",
                        url_result+json_response['data_id'])
        else:
            mod.display(module,
                        ioc,
                        "ERROR",
                        "MetaDefender json_response was not as expected, API may has been updated.")
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="MetaDefender response.code_status : %d" % (response_status))
    return None
