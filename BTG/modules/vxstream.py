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

import random
import json

from BTG.lib.async_http import store_request
from BTG.lib.io import module as mod


class Vxstream:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "SHA1", "SHA256", "domain", "IPv4", "IPv6", "URL"]
        self.search_method = "Online"
        self.description = "Search IOC in Hybrid Analysis"
        self.author = "Hicham Megherbi"
        self.creation_date = "20-10-2017"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "POST"
        # Specifing user_agent to avoid the 403
        self.headers = {'User-agent': 'Falcon Sandbox',
                        'Content-type': 'application/x-www-form-urlencoded',
                        'accept': 'application/json'}
        self.proxy = self.config["proxy_host"]

        self.vxstream_api()

    def vxstream_api(self):
        """
        VXstream API Connection
        """

        if 'vxstream_api_keys' in self.config:
            self.headers['api-key'] = random.Random(self.ioc).choice(self.config['vxstream_api_keys'])
        else:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        "Check if you have vxstream_api_keys_secret field in btg.cfg")
            return None

        if self.type in ["MD5", "SHA1", "SHA256"]:
            self.url = "https://www.hybrid-analysis.com/api/v2/search/hash"
            self.data = "hash="+self.ioc
        else:
            self.url = "https://www.hybrid-analysis.com/api/v2/search/terms"
            if self.type in ["IPv4", "IPv6"]:
                self.data = "host="+self.ioc
            elif self.type == "URL":
                self.data = "url="+self.ioc
            else:
                self.data = "domain="+self.ioc

        request = {'url': self.url,
                   'headers': self.headers,
                   'data': self.data,
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
        try:
            json_response = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        message_type="ERROR",
                        string="VxStream json_response was not readable.")
            return None

        if "count" in json_response and "search_terms" in json_response:
            if json_response["count"] > 0:
                verdict = json_response["result"][0]["verdict"]
                threat_score = json_response["result"][0]["threat_score"]
                type = json_response["search_terms"][0]["id"]
                url = "https://www.hybrid-analysis.com/advanced-search-results?terms[%s]=%s" % (type, ioc)
                mod.display(module,
                            ioc,
                            "FOUND",
                            "%s | %s/100 | %s" % (verdict, threat_score, url))
                return None
        elif json_response:
            verdict = json_response[0]["verdict"]
            threat_score = json_response[0]["threat_score"]
            url = "https://www.hybrid-analysis.com/sample/"+ioc
            mod.display(module,
                        ioc,
                        "FOUND",
                        "%s | %s/100 | %s" % (verdict, threat_score, url))
            return None
        mod.display(module,
                    ioc,
                    "NOT_FOUND",
                    "Nothing found in vxstream DB")
        return None
    else:
        mod.display(module,
                    ioc,
                    "ERROR",
                    "VXstream API connection status %d" % response_status)
        return None
