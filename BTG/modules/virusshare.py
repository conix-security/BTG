#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Hicham Megherbi
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

import requests

from lib.io import module as mod


class Virusshare:
    def __init__(self, ioc, type, config):
        self.config = config
        self.module_name = __name__.split(".")[1]
        self.types = ["MD5", "SHA1", "SHA256"]
        self.search_method = "Online"
        self.description = "Search IOC malware in VirusShare"
        self.author = "Hicham Megherbi"
        self.creation_date = "15-11-2017"
        self.type = type
        self.ioc = ioc

        if type in self.types and mod.allowedToSearch(self.search_method):
            self.search()
        else:
            mod.display(self.module_name, "", "INFO", "VirusShare module not activated")

    def serach_ioc(self):
        search_url = "https://virusshare.com/search.4n6"
        login_url = "https://virusshare.com/processlogin.4n6"
        login_page = "https://virusshare.com/login.4n6"

        auth = {'username': self.config['virusshare_username'],
                'password': self.config['virusshare_password']
                }

        header = {'User-Agent': self.config['user_agent']['User-Agent'],
                  'Host': 'virusshare.com',
                  'Referer': 'https://virusshare.com/',
                  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                  'Accept-Language': 'en-US,en;q=0.5',
                  'DNT': '1',
                  'Upgrade-Insecure-Requests': '1',
                  'connection': 'close'
                  }

        try:
            session = requests.Session()
            session.get(login_page, headers=header)
            authentification = session.post(login_url, data=auth)
            if authentification.status_code == 200:
                result = session.post(search_url, data={'search':self.ioc , 'start': '0'})
                if result.status_code == 200:
                    return result.content
                else:
                    return ""
            else:
                return ""

        except:
            raise
            return ""

    def extract_information(self, data):
        '''
        Extract all information page from VirusShare
        '''
        try:
            md5 = re.findall(r'(?<=<td>MD5<\/td><td>)[^<]*',data)
            if md5:
                md5 = md5[0]
            else:
                md5 = ""

            sha1 = re.findall(r'(?<=<td>SHA1<\/td><td>)[^<]*',data)
            if sha1:
                sha1 = sha1[0]
            else:
                sha1 = ""

            sha256 = re.findall(r'(?<=<td>SHA256<\/td><td>)[^<]*',data)
            if sha256:
                sha256 = sha256[0]
            else:
                sha256 = ""

            file_type = re.findall(r'(?<=<td>File\ Type<\/td><td\ colspan=2>)[^<]*',data)
            if file_type:
                file_type = file_type[0].replace("\n","")
            else:
                file_type = ""

            detections = re.findall(r'(?<=Detections<\/td><td\ colspan=2><pre>)[^<]*',data)
            if detections:
                detections = detections[0]
            else:
                detections = ""

            data = {'MD5': md5,
                    'SHA1': sha1,
                    'SHA256': sha256,
                    'DETECTIONS': detections,
                   }

            return data

        except:
            raise
            return {}

    def check_ioc(self, data, extract_info):
        '''
        Check if IOC Hash is found in VirusShare
        '''
        if not 'Search for "%s" returned no results.' % self.ioc in data:
            
            hashs = [extract_info['MD5'],
                     extract_info['SHA1'],
                     extract_info['SHA256'],
                     ]
            if self.ioc in hashs:
                return True
            else:
                return False
        elif 'NO BOTS! NO SCRAPERS!' in data:
              mod.display(self.module_name, self.ioc, "ERROR", "VirusShare login failed!")
              return False
        else:
            return False

    def search(self):
        try:
            mod.display(self.module_name, "", "INFO", "Searching...")
            data_page = self.serach_ioc()
            extract_info = self.extract_information(data_page)
            if self.check_ioc(data_page, extract_info):
                mod.display(self.module_name,
                            self.ioc,
                            "FOUND",
                            "Score: %d | %s" % (len(extract_info['DETECTIONS'].split("\n"))-1, "https://virusshare.com/"))

        except:
            pass
