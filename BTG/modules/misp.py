#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2017 Conix Cybersecurity
# Copyright (c) 2016-2017 Robin Marsollier
# Copyright (c) 2017 Alexandra Toussaint
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

from BTG.lib.async_http import store_request
from BTG.lib.config_parser import Config
from BTG.lib.io import module as mod

cfg = Config.get_instance()


class Misp:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "SHA1", "domain", "IPv4",
                      "IPv6", "URL", "SHA256", "SHA512"]
        self.search_method = "Onpremises"
        self.description = "Search IOC in MISP database"
        self.author = "Conix"
        self.creation_date = "07-10-2016"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "POST"
        self.headers = {'Content-Type': 'application/json','Accept': 'application/json'}
        self.proxy = self.config['proxy_host']
        self.verify = self.config['misp_verifycert']

        length = len(self.config['misp_url'])
        if length != len(self.config['misp_key']) and length <= 0:
            mod.display(self.module_name,
                        self.ioc,
                        "ERROR",
                        "MISP fields in btg.cfg are missfilled, checkout commentaries.")
            return None
        for indice in range(len(self.config['misp_url'])):
            misp_url = self.config['misp_url'][indice]
            misp_key = self.config['misp_key'][indice]
            self.Search(misp_url, misp_key, indice)

    def Search(self, misp_url, misp_key, indice):
        mod.display(self.module_name, "", "INFO", "Search in misp...")

        url = '%sattributes/restSearch/json' % (misp_url)
        self.headers['Authorization'] = misp_key
        payload = {'value': self.ioc, 'searchall': 1}
        data = json.dumps(payload)

        request = {'url': url,
                   'headers': self.headers,
                   'data': data,
                   'module': self.module_name,
                   'ioc': self.ioc,
                   'verbose': self.verbose,
                   'proxy': self.proxy,
                   'verify': self.verify,
                   'server_id': indice
                   }
        json_request = json.dumps(request)
        store_request(self.queues, json_request)


def response_handler(response_text, response_status, module, ioc, server_id):
    web_url = cfg['misp_url'][server_id]
    if response_status == 200:
        try:
            json_response = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        message_type="ERROR",
                        string="Misp json_response was not readable.")
            return None

        if "Attribute" in json_response["response"]:
            displayed = []
            for attr in json_response["response"]["Attribute"]:
                event_id = attr["event_id"]
                if event_id not in displayed:
                    displayed.append(event_id)
                    mod.display(module,
                                ioc,
                                "FOUND",
                                "Event: %sevents/view/%s" % (web_url,
                                                             event_id))
                    return None
            mod.display(module,
                        ioc,
                        "NOT_FOUND",
                        "Nothing found in Misp:%s database" % (web_url))
            return None
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="Misp connection status : %d" % (response_status))
