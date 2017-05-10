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

from lib.io import display
from lib.cache import Cache
import json

class Malshare():
    def __init__(self,ioc,type,config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        self.types = ["MD5","SHA256","SHA1"]
        self.search_method = "Online"
        self.description = "Search IOC in Malshare database"
        self.author = "Conix"
        self.creation_date = "12-04-2017"
        self.type = type
        self.ioc = ioc
        if type in self.types:
            self.search()



    def search(self):
        display(self.module_name, self.ioc, "INFO", "Searching...")
        url = "http://malshare.com/"
        if "malshare_api_key" in self.config :
            if self.config["malshare_api_key"] :
                paths = [
                    "api.php?api_key=%s&action=details&hash=%s" %(self.config["malshare_api_key"],self.ioc)
                ]
                for path in paths:
                    try :
                        content = json.loads(Cache(self.module_name, url, path, self.search_method).content)
                        safe_urls=[]
                        for malware_url in content["SOURCES"]:
                            safe_urls.append(malware_url.replace("http","hxxp"))
                        display(self.module_name,self.ioc,"FOUND", "%s | %s%s" % (safe_urls,url,path))
                        return
                    except :
                        pass
        else :
            display(self.module_name, message_type="ERROR", string="You must have a malshare api key to use this module ")