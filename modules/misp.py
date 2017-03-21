#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2017 Conix Cybersecurity
# Copyright (c) 2016-2017 Robin Marsollier
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
import config, json
import warnings

try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from pymisp import PyMISP
except:
	if misp_enabled:
		display(__name__.split(".")[1], message_type="ERROR", string="You need to get 'pymisp' library (available here: https://github.com/MISP/PyMISP)")
    	exit()

class Misp:
    def __init__(self, ioc, type):
    	if config.misp_enabled:
            self.module_name = __name__.split(".")[1]
            self.types = ["MD5", "SHA1", "domain", "IPv4", "IPv6", "URL", "SHA256", "SHA512"]
            self.search_method = "Offline"
            self.description = "Search IOC in MISP database"
            self.author = "Conix"
            self.creation_date = "07-10-2016"
            self.type = type
            self.ioc = ioc
            if type in self.types:
                self.Search()

    def Search(self):
        display(self.module_name, self.ioc, "INFO", "Search in misp...")
        try:
            m = PyMISP(config.misp_url, config.misp_key, config.misp_verifycert, 'json')
        except Exception, e:
            display(self.module_name, self.ioc, "ERROR", e)
            return    
        result = m.search_all(self.ioc)
        try:
            for event in result["response"]:
                tag_display = ""
                try:
                    for tag in event["Event"]["Tag"]:
                        if tag["name"].split(":")[0] in config.misp_tag_display:
                            if len(tag_display) == 0:
                                tag_display = "["
                            else:
                                tag_display = "%s|"%tag_display
                            tag_display = "%s%s"%(tag_display, tag["name"])
                except:
                    pass
                if len(tag_display) != 0:
                    tag_display = "%s]"%tag_display
                display(self.module_name, self.ioc, "FOUND", "%s Event: %sevents/view/%s"%(tag_display, config.misp_url, event["Event"]["id"]))
        except:
            try:
                if result['message'] == "No matches":
                    pass
                elif "Authentication failed" in result['message']:
                    display(__name__.split(".")[1], message_type="ERROR", string=result['message'])
            except:
                pass
