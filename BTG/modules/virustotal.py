#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2017 Conix Cybersecurity
# Copyright (c) 2017 Alexandra Toussaint
# Copyright (c) 2017 Robin Marsollier
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

from requests import post
from json import loads
from random import choice, randint
from time import sleep
from lib.io import module as mod
import ast
import json

class Virustotal:
    """
        This module allow you to search IOC in Virustotal
    """
    def __init__(self, ioc, type, config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        self.types = ["MD5", "SHA1", "SHA256", "URL", "IPv4", "domain"]
        self.search_method = "Online"
        self.description = "Search IOC in VirusTotal database"
        self.author = "Conix"
        self.creation_date = "13-09-2016"
        self.type = type
        self.ioc = ioc

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
            self.searchURL()
        else:
            self.searchReport()

    def searchReport(self):
        self.url = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {"resource": self.ioc,
                      "apikey": self.key,
                      "allinfo": 1}
        while True:
            req = post(
                        self.url,
                        headers=self.config["user_agent"],
                        proxies=self.config["proxy_host"],
                        timeout=self.config["requests_timeout"],
                        data = parameters
                    )
            if req.status_code == 200 :
                response_content = req.text
                try:
                    json_content = json.loads(response_content)
                    break
                except :
                    mod.display(self.module_name, self.ioc, "WARNING", "Virustotal json decode fail. Blacklisted/Bad API key?")
                    return None
            else :
                mod.display(self.module_name, self.ioc, "ERROR", "VirusTotal returned "+ str(req.status_code))
                return None
        try:
            if json_content["positives"]:
                mod.display(self.module_name,
                            self.ioc,
                            "FOUND",
                            "Score: %s/%s | %s"%(json_content["positives"],
                                                 json_content["total"],
                                                 json_content["permalink"]))
        except:
            pass

    def searchURL(self):
        self.url = "http://www.virustotal.com/vtapi/v2/url/report"
        parameters = {"resource": self.ioc,
                      "apikey": self.key}
        while True:
            req = post(
                self.url,
                headers=self.config["user_agent"],
                proxies=self.config["proxy_host"],
                timeout=self.config["requests_timeout"],
                data = parameters
            )
            try:
                json_content = json.loads(req.text)
                break
            except:
                mod.display(self.module_name, self.ioc, "WARNING", "Virustotal json decode fail. Blacklisted/Bad API key?")
                return None
        try:
            if json_content["positives"]:
                mod.display(self.module_name,
                            self.ioc,
                            "FOUND",
                            "Score: %s/%s | %s"%(json_content["positives"],
                                                 json_content["total"],
                                                 json_content["permalink"]))
        except:
            pass
