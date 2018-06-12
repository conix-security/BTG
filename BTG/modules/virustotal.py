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

from random import choice, randint
from time import sleep
import ast
import json

from BTG.lib.io import module as mod
from BTG.lib.async_http import store_request

class Virustotal:
    """
        This module allow you to search IOC in Virustotal
    """
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "SHA1", "SHA256", "URL", "IPv4", "domain"]
        self.search_method = "Online"
        self.description = "Search IOC in VirusTotal database"
        self.author = "Conix"
        self.creation_date = "13-09-2016"
        self.type = type
        self.ioc = ioc
        self.queues = queues
        self.verbose = "POST"
        self.headers = self.config["user_agent"]
        self.proxy = self.config["proxy_host"]

        if type in self.types and mod.allowedToSearch(self.search_method):
            self.search()
        else:
            mod.display(self.module_name, "", "INFO", "VirusTotal module not activated")

    def search(self):
        mod.display(self.module_name, "", "INFO", "Search in VirusTotal ...")
        try:
            if "virustotal_api_keys" in self.config:
                self.key = choice(self.config["virustotal_api_keys"])
            else:
                mod.display(self.module_name,
                            message_type="ERROR",
                            string="Check if you have virustotal_api_keys field in config.ini")
        except:
            mod.display(self.module_name, self.ioc, "ERROR", "Please provide your authkey.")
            return
        if self.type in ["URL", "domain", "IPv4"]:
            request = self.searchURL()
        else:
            request = self.searchReport()
        store_request(self.queues, request)

    def searchReport(self):
        self.url = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {"resource": self.ioc,
                      "apikey": self.key,
                      "allinfo": 1
                      }
        request = {"url" : self.url,
                   "headers" : self.headers,
                   "data" : parameters,
                   "module" : self.module_name,
                   "ioc" : self.ioc,
                   "verbose" : self.verbose,
                   "proxy" : self.proxy
                   }
        json_request = json.dumps(request)
        return json_request

    def searchURL(self):
        self.url = "http://www.virustotal.com/vtapi/v2/url/report"
        parameters = {"resource": self.ioc,
                      "apikey": self.key
                      }
        request = {"url" : self.url,
                   "headers" : self.headers,
                   "data" : parameters,
                   "module" : self.module_name,
                   "ioc" : self.ioc,
                   "verbose" : self.verbose,
                   "proxy" : self.proxy
                   }
        json_request = json.dumps(request)
        return json_request

def response_handler(response_text, response_status, module, ioc, server_id=None):
    if response_status == 200 :
        try:
            json_content = json.loads(response_text)
        except:
            mod.display(module,
                        ioc,
                        message_type="ERROR",
                        string="VirusTotal json_response was not readable.")
            return None
        if "positives" in json_content and json_content["positives"] > 0:
            mod.display(module,
                        ioc,
                        "FOUND",
                        "Score: %d/%d | %s"%(json_content["positives"],
                                             json_content["total"],
                                             json_content["permalink"]))
    else:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="VirusTotal response.code_status : %d" % (response_status))
