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

import requests
import json
from lib.io import module as mod
from random import choice, randint
import time

import asyncio
from aiohttp import ClientSession


class googlesb():
    """
        This module performs a Safe Browsing Lookup to Google API
    """
    def __init__(self, ioc, type, config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        # supported type : hash and digest SHA256, URL
        self.types = ["URL", "domain"]
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
            # TODO
            # Dead code ?
            else:
                mod.display(self.module_name,
                            message_type="ERROR",
                            string="Check if you have googlesb_api_keys field in config.ini")
        except:
            mod.display(self.module_name, self.ioc, "ERROR", "Please provide your Google API key.")
            return None

        server = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+api_key

        # TODO
        # Does not work 400 status_code
        if self.type == "SHA256":
            threatType = "EXECUTABLE"
            threatTypeEntry = "hash"
        # Does not work 400 status_code
        elif self.type in ["IPv4", "IPv6"]:
            threatType = "IP_RANGE"
            threatTypeEntry = "ip"
        else :
            threatType = "URL"

        payload = {"threatInfo":
                    {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM", "ALL_PLATFORMS", "WINDOWS", "LINUX", "OSX", "ANDROID", "IOS"],
                    "threatEntryTypes": [threatType],
                    "threatEntries": [{threatType.lower(): str(self.ioc)}]
                    }
                  }

        json_payload = json.dumps(payload)
        # response = requests.post(server, data=json_payload)
        loop = asyncio.get_event_loop()
        future = asyncio.ensure_future(run(self, server, json_payload))
        loop.run_until_complete(future)


async def fetch(self, url, data, session):
    async with session.post(url, data=data) as response:
        return await response.text()

async def run(self, url, data):
    tasks = []

    # Fetch all responses within one Client session,
    # keep connection alive for all requests.
    async with ClientSession() as session:
        task = asyncio.ensure_future(fetch(self, url, data, session))
        tasks.append(task)

        responses = await asyncio.gather(*tasks)

        for response in responses :
            temp = json.loads(response)
            try:
                if 'matches' in temp:
                    list_platform = set([])
                    list_type = set([])
                    for m in temp['matches'] :
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
                return None

        return responses
