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

class metadefender:
    """
        This module performs a Safe Browsing Lookup to Google API
    """
    def __init__(self, ioc, type, config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        self.types = ["MD5", "SHA1", "SHA256", "SHA512", "IPv4", "IPv6" ]
        self.search_method = "Online"
        self.description = "Search IOC in MetaDefender"
        self.author = "Conix"
        self.creation_date = "13-04-2018"
        self.type = type
        self.ioc = ioc

        if type in self.types and mod.allowedToSearch(self.search_method):
            self.Search()
        else:
            mod.display(self.module_name, "", "INFO", "MetaDefender module not activated")


    def Search(self):
        mod.display(self.module_name, "", "INFO", "Search in MetaDefender ...")

        headers = {'apikey' : ''}
        try:
            if 'metadefender_api_keys' in self.config:
                api_key = choice(self.config['metadefender_api_keys'])
                headers['apikey'] = api_key
            else:
                mod.display(self.module_name,
                            self.ioc,
                            message_type="ERROR",
                            string="Check if you have metadefender_api_keys field in config.ini")
                return None
        except:
            mod.display(self.module_name, self.ioc, "ERROR", "Please provide your MetaDefender key")
            return None

        # URL building
        url="https://api.metadefender.com/"
        branch = 0
        if self.type in ["MD5", "SHA1", "SHA256", "SHA512"]:
            url = url + "v2/hash/" + self.ioc
            branch = 1
        elif self.type in ["IPv4", "IPv6"]:
            url = url + "v1/scan/" + self.ioc
            branch = 2

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            try:
                json_response = json.loads(response.text)
            except:
                # TODO
                # copied from virustotal module, why should we put the worker in sleep mode ?
                mod.display(self.module_name,
                            self.ioc,
                            message_type="WARNING",
                            string="MetaDefender json_response was not readable. (Sleep 10sec).")
                sleep(randint(5, 10))
                return None
        else:
            mod.display(self.module_name,
                        self.ioc,
                        message_type="ERROR",
                        string="MetaDefender API connection status %d" % response.status_code)
            return None

        try:
            if branch == 1:
                if json_response["scan_results"]["total_detected_avs"] > 0:
                    mod.display(self.module_name,
                            self.ioc,
                            "FOUND",
                            "Score : %d/%d | %s" % (json_response["scan_results"]["total_detected_avs"], json_response["scan_results"]["total_avs"], url))
            elif  branch == 2:
                if json_response["detected_by"] > 0:
                    mod.display(self.module_name,
                                self.ioc,
                                "FOUND",
                                "Score : %d/%d | %s" % (len(json_response["scan_results"]),json_response["detected_by"], url))
            else:
                mod.display(self.module_name,
                            self.ioc,
                            "ERROR",
                            "Oops something bad happen, if so, there must be a mistake in code.")
        except:
            pass
