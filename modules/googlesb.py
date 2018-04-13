#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Tanguy Becam
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
import json
from lib.io import module as mod
from random import choice, randint

class googlesb:
    """
        This module performs a Safe Browsing Lookup to Google API
    """
    def __init__(self, ioc, type, config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        # supported type : hash and digest SHA256, URL
        self.types = ["URL", "SHA256", "IPv4", "IPv6" ]
        # googleSB can run on a local database with a 30min refresh by default
        self.search_method = "Online"
        self.description = "Search IOC in GoogleSafeBrowsing database"
        self.author = "Conix"
        self.creation_date = "11-04-2018"
        self.type = type
        self.ioc = ioc

        if type in self.types and mod.allowedToSearch(self.search_method):
            self.lookup_API()
        else:
            mod.display(self.module_name, "", "INFO", "googlesb module not activated")
            return None

    def lookup_API(self):
        mod.display(self.module_name, "", "INFO", "Search in Google Safe Browsing ...")

        try:
            if 'googlesb_api_keys' in self.config:
                api_key = choice(self.config['googlesb_api_keys'])
            else:
                mod.display(self.module_name,
                            message_type="ERROR",
                            string="Check if you have googlesb_api_keys field in config.ini")
        except:
            mod.display(self.module_name, self.ioc, "ERROR", "Please provide your Google API key.")
            return None

        server = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+api_key

        # TODO
        # The following switch case is there to fill json body request
        if self.type == "SHA256":
            threatType = "EXECUTABLE"
            threatTypeEntry = "hash"
        # This condition shouldn't be right, can't find IP addresses in API docs, should result in a 400 status_code
        elif self.type in ["IPv4", "IPv6"]:
            threatType = "IP_RANGE"
            threatTypeEntry = "ip"
        else :
            threatType = self.type


        payload = {"threatInfo":
                    {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM", "ALL_PLATFORMS", "WINDOWS", "LINUX", "OSX", "ANDROID", "IOS"],
                    "threatEntryTypes": [threatType],
                    "threatEntries": [{threatType.lower(): str(self.ioc)}]
                    }
                  }

        json_payload = json.dumps(payload)

        response = requests.post(server, data=json_payload)

        if response.status_code == 200:
            try :
                json_response = json.loads(response.text)
            except :
                # TODO
                # copied from virustotal module, why should we put the worker in sleep mode ?
                mod.display(self.module_name,
                            self.ioc,
                            message_type="WARNING",
                            string="GoogleSafeBrowsing json_response was not readable. (Sleep 10sec).")
                sleep(randint(5, 10))
                return None
        else:
            mod.display(self.module_name,
                        message_type="ERROR",
                        string="GoogleSafeBrowsing API connection status %d" % response.status_code)
            return None

        try:
            if 'matches' in json_response:
                list_platform = set([])
                list_type = set([])
                for m in json_response['matches'] :
                    list_type.add(m['threatType'])
                    list_platform.add(m['platformType'])

                mod.display(self.module_name,
                            self.ioc,
                            "FOUND",
                            "ThreatType: %s | PlatformType: %s" % (list_type, list_platform))
            else:
                    mod.display(self.module_name,
                                self.ioc,
                                "INFO",
                                "Nothing found in Google Safe Browsing")
        except:
            pass
