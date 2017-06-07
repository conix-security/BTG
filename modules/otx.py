#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2017 Conix Cybersecurity
# Copyright (c) 2016-2017 Hicham Megherbi
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

from config_parser import Config
from BTG import BTG
from lib.io import display

try:
    from OTXv2 import OTXv2
    import IndicatorTypes
except:
    display(__name__.split(".")[1], message_type="ERROR", string="You need to get 'OTXv2' library (available here: https://github.com/AlienVault-Labs/OTX-Python-SDK)")
    exit()


class Otx:
    def __init__(self, ioc, type,config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        self.types = ["MD5", "SHA1", "domain", "IPv4", "IPv6","URL", "SHA256"]
        self.search_method = "Online"
        self.description = "Search IOC in Alienvault database"
        self.author = "Hicham Megherbi"
        self.creation_date = "13-04-2016"
        self.type = type
        self.ioc = ioc
        if type in self.types and BTG.allowedToSearch(self.search_method):
            self.Search()

    def Search(self):
        display(self.module_name, self.ioc, "INFO", "Search in Alienvault...")
        try:
            if "otx_api_keys" in self.config :
                otx = OTXv2(self.config["otx_api_keys"])
                if self.type == "IPv4":
                   indicator = IndicatorTypes.IPv4
                if self.type == "IPv6":
                   indicator = IndicatorTypes.IPv6
                if self.type == "domain":
                   indicator = IndicatorTypes.DOMAIN
                if self.type == "URL":
                   indicator = IndicatorTypes.URL
                if self.type == "MD5":
                   indicator = IndicatorTypes.FILE_HASH_MD5
                if self.type == "SHA1":
                   indicator = IndicatorTypes.FILE_HASH_SHA1
                if self.type == "SHA256":
                   indicator = IndicatorTypes.FILE_HASH_SHA256
                result = otx.get_indicator_details_full(indicator, self.ioc)
            else :
                display(self.module_name,message_type="ERROR", string= "Please check if you have otx_api_keys field in config.ini")
        except Exception, e:
            display(self.module_name, self.ioc, "ERROR", e)
            return    
        try:
            if  self.ioc == str( result["general"]["indicator"]):  
               _id =str(result["general"]["pulse_info"]["pulses"][0]["id"])

               tags=""
               for tag in result["general"]["pulse_info"]["pulses"][0]["tags"] :
                   tags= tags+"%s "%tag
               display(self.module_name, self.ioc, "FOUND", "Tags: %s| https://otx.alienvault.com/pulse/%s/"%( tags, _id))
        except:
             pass
