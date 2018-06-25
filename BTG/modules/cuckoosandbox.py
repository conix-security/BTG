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

import json
from platform import system

from BTG.lib.config_parser import Config
from BTG.lib.io import module as mod
from BTG.lib.async_http import store_request

cfg = Config.get_instance()
if system() != "Windows":
    import requests_cache
    requests_cache.install_cache('%sBTG' % cfg["sqlite_path"])


class Cuckoosandbox:
    """
        This module allow you to search IOC in CuckooSandbox database
    """
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = [
            "MD5", "SHA256"
        ]
        self.search_method = "Onpremises"
        self.description = "Search IOC in CuckooSandbox database"
        self.author = "Conix"
        self.creation_date = "02-03-2017"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "GET"
        self.headers = self.config["user_agent"]
        self.proxy = self.config["proxy_host"]

        if type in self.types and mod.allowedToSearch(self.search_method):
            length = len(self.config['cuckoosandbox_api_url'])
            if  length != len(self.config['cuckoosandbox_web_url']) and length <= 0:
                mod.display(self.module_name,
                            self.ioc,
                            "ERROR",
                            "Cuckoosandbox fields in btg.cfg are missfilled, checkout commentaries.")
                return None

            for indice in range(len(self.config['cuckoosandbox_api_url'])):
                api_url = self.config['cuckoosandbox_api_url'][indice]
                web_url = self.config['cuckoosandbox_web_url'][indice]
                self.search(api_url, web_url, indice)
        else:
            mod.display(self.module_name, "", "INFO", "Cuckoosandbox module not activated")
            return None

    def search(self, api_url, web_url, indice):
        mod.display(self.module_name, "", "INFO", "Searching...")
        if ("cuckoosandbox_api_url" in self.config and
            "user_agent" in self.config and
            "proxy_host" in self.config and
            "requests_timeout" in self.config):

            if self.type in ["MD5"]:
                url = "%s/files/view/md5/%s" % (api_url, self.ioc)
            elif self.type in ["SHA256"]:
                url = "%s/files/view/sha256/%s" % (api_url, self.ioc)

            request = {'url' : url,
                       'headers' : self.headers,
                       'module' : self.module_name,
                       'ioc' : self.ioc,
                       'verbose' : self.verbose,
                       'proxy' : self.proxy,
                       'server_id' : indice
                       }
            json_request = json.dumps(request)
            store_request(self.queues, json_request)
        else:
            mod.display(self.module,
                        self.ioc,
                        "ERROR",
                        "Check if you have filled cuckoosandbox fields in btg.cfg")


def response_handler(response_text, response_status, module, ioc, server_id):
        web_url = cfg['cuckoosandbox_api_url'][server_id]
        if response_status == 200 :
            try:
                json_response = json.loads(response_text)
            except:
                mod.display(module,
                            ioc,
                            "ERROR",
                            "CuckooSandbox json_response was not readable.")
                return None

            id_analysis = json_response["sample"]["id"]
            mod.display("%s_remote" % module,
                        ioc,
                        "FOUND",
                        "%s/view/%s" % (web_url, id_analysis))
        else:
            mod.display(module,
                        ioc,
                        "ERROR",
                        "CuckooSandbox connection status : %d for server : %s" % (response_status,web_url))
