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

import config
from BTG import BTG
from lib.io import display
import urllib
import urllib2
from json import loads
from time import sleep
from random import randint, choice

class Virustotal:
    """
        This module allow you to search IOC in Virustotal 
    """
    def __init__(self, ioc, type):
        if config.virustotal_enabled:
            self.module_name = __name__.split(".")[1]
            self.types = ["MD5", "SHA1", "SHA256", "URL", "IPv4", "domain"]
            self.search_method = "Online"
            self.description = "Search IOC in VirusTotal database"
            self.author = "Conix"
            self.creation_date = "13-09-2016"
            self.type = type
            self.ioc = ioc
            if type in self.types and BTG.allowedToSearch(self.search_method):
                if len(config.proxy_host["https"]) > 0:
                    proxy = urllib2.ProxyHandler({'https': config.proxy_host["https"]})
                    opener = urllib2.build_opener(proxy)
                else:
                    opener = urllib2.build_opener()
                urllib2.install_opener(opener)
                try:
                    self.key = choice(config.virustotal_API_keys)
                except:
                    display(self.module_name, self.ioc, "ERROR", "Please provide your authorization key.")
                    return
                display(self.module_name, self.ioc, "INFO", "Searching...")
                
                if self.type in ["URL", "domain", "IPv4"]:
                    self.searchURL()
                else:
                    self.searchReport()
                
    def searchReport(self):
        self.url = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {"resource": self.ioc,
                      "apikey": self.key,
                      "allinfo":1}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(self.url, data)
        response = urllib2.urlopen(req)
        try:
            json_content = loads(response.read())
        except:
            display(self.module_name, self.ioc, "ERROR", "VirusTotal API seems to be down.")
        try:
            display(self.module_name, self.ioc, "FOUND", json_content["permalink"])
        except:
            pass

    def searchURL(self):
        self.url =  "http://www.virustotal.com/vtapi/v2/url/report"
        parameters = {"resource": self.ioc,
                      "apikey": self.key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(self.url, data)
        while True:
            try:
                response = urllib2.urlopen(req).read()
                json_content = loads(response)
                break
            except:
                display(self.module_name, self.ioc, "INFO", "Virustotal json decode fail. Mabye: Blacklisted/Bad API key (Sleep for 10 seconds).")
                sleep(randint(5, 10))
                pass
        try:
            if json_content["positives"]:
                display(self.module_name, self.ioc, "FOUND", json_content["permalink"])
        except:
            pass
