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
        self.types = ["MD5", "SHA1", "SHA256", "SHA512"]
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
        url="https://api.metadefender.com/v2/hash/" + self.ioc

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            url_result = "https://www.metadefender.com/results#!/hash/"
            try:
                json_response = json.loads(response.text)
                print(json_response)
            except:
                mod.display(self.module_name,
                            self.ioc,
                            message_type="WARNING",
                            string="MetaDefender json_response was not readable.")
                return None

            if json_response[self.ioc.upper()] == "Not Found":
                return None
            elif json_response['scan_all_result_a'] == "Clear":
                return None
            elif json_response['scan_all_result_a'] == "Infected" \
                or json_response['scan_all_result_a'] == "Suspicious":
                mod.display(self.module_name,
                            self.ioc,
                            message_type="FOUND",
                            string=url_result+json_response['data_id'])
            else:
                mod.display(self.module_name,
                            self.ioc,
                            message_type="ERROR",
                            string="MetaDefender json_response was not as expected, API may has been updated.")

        else:
            mod.display(self.module_name,
                        self.ioc,
                        message_type="ERROR",
                        string="MetaDefender API connection status %d" % response.status_code)
            return None
