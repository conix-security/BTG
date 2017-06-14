#!/usr/bin/python
# Copyright (c) 2016-2017 Conix Cybersecurity
# Copyright (c) 2017 Alexandra Toussaint
# Copyright (c) 2017 Robin Marsollier
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

import datetime
import sys
from os import chmod, mkdir, remove, stat
from os.path import exists, isdir
from time import mktime

import requests
from requests.exceptions import ConnectionError, ReadTimeout

from config_parser import Config
from lib.io import module as mod


class Cache:
    def __init__(self, module_name, url, filename, search_method):
        self.config = Config.get_instance()
        self.module_name = module_name
        self.url = url
        self.filename = self.new_filename = filename
        self.temp_folder = "%s%s/"%(self.config["temporary_cache_path"], self.module_name)
        position = 0
        filename_copy = self.filename
        if not self.filename.isalnum():
            filename_copy = self.filename.replace("_", "")
            for pos, char in enumerate(filename_copy):
                if not char.isalnum() and char != '.':
                    position = pos
        self.new_filename = filename_copy[position:]
        self.temp_file = "%s%s"%(self.temp_folder, self.new_filename)

        self.createModuleFolder()
        if self.checkIfUpdate():
            if mod.allowedToSearch(search_method):
                self.downloadFile()
        self.content = self.getContent()

    def getContent(self):
        f = ""
        if exists(self.temp_file):
            f = open(self.temp_file).read()
        return f

    def downloadFile(self):
        """
            Get file from web
        """
        mod.display("%s.cache"%self.module_name,
                    message_type="DEBUG",
                    string="Update %s%s"%(self.url, self.filename))
        full_url = "%s%s"%(self.url, self.filename)
        try:
            r = requests.get(
                full_url,
                stream=True, headers=self.config["user_agent"],
                proxies=self.config["proxy_host"],
                timeout=self.config["requests_timeout"]
            )
        except ConnectionError as e:
            mod.display("%s.cache"%self.module_name,
                        message_type="ERROR",
                        string=e)
            return
        except ReadTimeout as e:
            mod.display("%s.cache"%self.module_name,
                        message_type="ERROR",
                        string="Timeout: %s"%(full_url))
            return
        except:
            raise
        if r.status_code == 200:
            if not exists("%s.lock"%self.temp_file):
                open("%s.lock"%self.temp_file, 'a').close()
                chmod("%s.lock"%self.temp_file, 0o777)
                if exists(self.temp_file):
                    to_chmod = False
                else:
                    to_chmod = True
                with open(self.temp_file, 'wb') as f:
                    for chunk in r:
                        f.write(chunk)
                if to_chmod:
                    chmod(self.temp_file, 0o777)
                remove("%s.lock"%self.temp_file)
        else:
            mod.display("%s.cache"%self.module_name,
                        message_type="ERROR",
                        string="Response code: %s | %s%s"%(r.status_code, self.url, self.filename))

    def checkIfUpdate(self):
        """
            True: Need to be updated
            False: Nothing to do
        """
        if exists(self.temp_file):
            if not self.compareUpdatedDate():
                return False
        return True

    def compareUpdatedDate(self):
        """
            Compare date now and edited date
        """
        if self.config["temporary_cache_update"] <= 0:
            return False
        date_to_compare = datetime.datetime.now() - datetime.timedelta(seconds=self.config["temporary_cache_update"]*60)
        last_update = stat(self.temp_file).st_mtime
        if last_update < int(mktime(date_to_compare.timetuple())):
            # Need to update
            return True
        # Don't need
        return False

    def createModuleFolder(self):
        if not isdir(self.config["temporary_cache_path"]):
            try:
                mkdir(self.config["temporary_cache_path"])
            except:
                mod.display("%s.cache"%self.module_name,
                            message_type="ERROR",
                            string="Unable to create %s directory. (Permission denied)"%self.config["temporary_cache_path"])
                sys.exit()
            chmod(self.config["temporary_cache_path"], 0o777)
        if not isdir(self.temp_folder):
            mkdir(self.temp_folder)
            chmod(self.temp_folder, 0o777)
