#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Hicham Megherbi
# Copyright (c) 2017 Lancelot Bogard
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

from BTG.lib.io import module as mod

class Viper:
    def __init__(self, ioc, type, config, queues):
        self.config = config
        self.module_name = __name__.split(".")[-1]
        self.types = ["MD5", "SHA1", "SHA256", "URL", "domain", "IPv4"]
        self.search_method = "Onpremises"
        self.description = "Search IOC in Viper Database"
        self.author = "Hicham Megherbi"
        self.creation_date = "21-10-2017"
        self.type = type
        self.ioc = ioc

        if type in self.types and mod.allowedToSearch(self.search_method):
            length = len(self.config['viper_server'])
            if  length != len(self.config['viper_api_key']) and length <= 0:
                mod.display(self.module_name,
                            message_type="ERROR",
                            string="Viper fields in btg.cfg are missfilled, checkout commentaries.")
                return
            for indice in range(len(self.config['viper_server'])):
                server = self.config['viper_server'][indice]
                api_key = self.config['viper_api_key'][indice]
                self.Search(server,api_key)
        else:
            mod.display(self.module_name, "", "INFO", "Viper module not activated")

    def viper_api(self, server, api_key):
        """
        Viper API Connection
        """
        if self.type in ["MD5", "SHA1", "SHA256"]:
            url = "%s/api/v3/project/default/malware/?search=%s" %(server, self.ioc)
        if self.type in ["domain", "URL", "IPv4"]:
            url = "%s/api/v3/project/default/note/?search=%s"%(server, self.ioc)
        headers = {'Authorization': 'Token %s' % api_key}
        response = requests.get(url,
                                headers=headers,
                                proxies=self.config["proxy_host"],
                                timeout=self.config["requests_timeout"])
        if response.status_code == 200:
            response_json = response.json()
            if response_json["count"] != 0:
                return response_json
            else:
                return None
        else:
            mod.display(self.module_name,
                        message_type="ERROR",
                        string="Viper API connection status %d" % response.status_code)
            return None

    def checkToken(self, server, api_key):
        headers = {'Authorization': 'Token %s'% api_key}
        response = requests.get("%s/api/v3/test-auth/"%(server), headers=headers)
        content = json.loads(response.text)
        try:
            if "Authentication validated successfully" in content["message"]:
                return True
        except KeyError:
            return False


    def Search(self, server, api_key):
        mod.display(self.module_name, "", "INFO", "Search in Viper ...")

        try:
            if "viper_server" in self.config and "viper_api_key" in self.config:
                if not self.checkToken(server, api_key):
                    mod.display(self.module_name, self.ioc, "ERROR", "Bad API key")
                    return
                if self.type in self.types:
                    result_json = self.viper_api(server, api_key)
            else:
                mod.display(self.module_name,
                            message_type=":",
                            string="Please check if you have viper fields in btg.cfg")
        except Exception as e:
            mod.display(self.module_name, self.ioc, "ERROR", e)
            return

        if result_json:
            if self.type in ["MD5", "SHA1", "SHA256"]:
                result_json = result_json["results"][0]
                id = " ID: %d |"%result_json["data"]["id"]
                name  = " Filename: %s"%result_json["data"]["name"]
                tag_final = ""
                try:
                    for tag in result_json["data"]["tag_set"]:
                        if len(tag_final) == 0:
                            tag_final = tag["data"]["tag"]
                        else:
                            tag_final = "%s, %s"%(tag_final, tag["data"]["tag"])
                except:
                    pass
                if len(tag_final) != 0:
                    tags = "Tags: %s |"%tag_final
                else:
                    tags = ""
                mod.display(self.module_name,
                            self.ioc,
                            "FOUND",
                            "%s%s%s" % (tags, id, name))

            elif self.type in ["URL", "domain", "IPv4"]:
                for element in result_json["results"]:
                    for malware in element["data"]["malware_set"]:
                        mod.display(self.module_name,
                                self.ioc,
                                "FOUND",
                                "ID: %s | Filename: %s | SHA1: %s" % (
                                    malware["data"]["id"],
                                    malware["data"]["name"],
                                    malware["data"]["sha1"]))
