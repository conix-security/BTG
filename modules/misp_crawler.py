#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2017 Conix Cybersecurity
# Copyright (c) 2016-2017 Lancelot Bogard
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

import re
import warnings
from lib.io import display
import config
import requests
warnings.filterwarnings("ignore")

class Misp_Crawler:
    def __init__(self, ioc, type):
        if config.misp_crawler_enabled:
            self.module_name = __name__.split(".")[1]
            self.types = ["MD5", "SHA1", "domain", "IPv4", "IPv6", "URL", "SHA256", "SHA512"]
            self.search_method = "Online"
            self.description = "Crawl MISP searching for IOC"
            self.author = "Conix"
            self.creation_date = "21-03-2017"
            self.type = type
            self.ioc = ioc
            if type in self.types:
                self.Search()

    def Search(self):
        display(self.module_name, self.ioc, "INFO", "Search in misp...")
        with requests.Session() as s:
            self.loginRequest(s)
            allEvents = self.searchAttribute(s)
            for event in allEvents:
                display(self.module_name, self.ioc, "FOUND", "Event: %s/events/view/%s"%(config.misp_crawler_url, event))

    def searchAttribute(self, s):
        response = s.get(
            "%s/attributes/search"%config.misp_crawler_url,
            headers=config.user_agent,
            verify=config.misp_crawler_verifycert
        )
        token_key, token_fields = self.getTokens(response.text)
        data = {
            '_method': 'POST',
            'data[_Token][key]': token_key,
            'data[Attribute][keyword]': self.ioc,
            'data[Attribute][attributetags]': '',
            'data[Attribute][keyword2]': '',
            'data[Attribute][tags]': '',
            'data[Attribute][org]': '',
            'data[Attribute][type]': 'ALL',
            'data[Attribute][category]': 'ALL',
            'data[Attribute][ioc]': '0',
            'data[Attribute][alternate]': '0',
            'data[_Token][fields]': token_fields,
            'data[_Token][unlocked]': ''
        }
        s.headers.update(
            {'referer': "%s/attributes/search"%config.misp_crawler_url}
        )
        response = s.post(
            "%s/attributes/search"%config.misp_crawler_url,
            data=data, headers=config.user_agent,
            verify=config.misp_crawler_verifycert
        )
        return self.getAllEvents(response.text)

    def loginRequest(self, s):
        response = s.get(
            "%s/users/login"%config.misp_crawler_url,
            headers=config.user_agent,
            verify=config.misp_crawler_verifycert
        )
        token_key, token_fields = self.getTokens(response.text)
        data = {
            '_method': 'POST',
            'data[_Token][key]': token_key,
            'data[User][email]': config.misp_crawler_login,
            'data[User][password]': config.misp_crawler_password,
            'data[_Token][fields]': token_fields,
            'data[_Token][unlocked]': ''
        }
        response = s.post(
            "%s/users/login"%config.misp_crawler_url,
            data=data,
            headers=config.user_agent,
            verify=config.misp_crawler_verifycert
        )

    def getAllEvents(self, response):
        events = []
        for event in re.findall(r"events\/view\/([0-9]+)+\" ", response):
            if event not in events:
                events.append(event)
        return events

    def getTokens(self, response):
        token_key = re.search(r"data\[_Token\]\[key\]\" value=\"(.+)\" ", response).group(1)
        token_fields = re.search(r"data\[_Token\]\[fields\]\" value=\"(.+%3A)\"", response).group(1)
        return token_key, token_fields
