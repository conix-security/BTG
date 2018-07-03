#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2018 Conix Cybersecurity
# Copyright (c) 2017 Alexandra Toussaint
# Copyright (c) 2017 Robin Marsollier
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

from os import chmod, mkdir, makedirs, remove, stat
from os.path import exists, isdir
from requests.exceptions import ConnectionError, ReadTimeout
from time import mktime
import datetime
import requests
import sys

from BTG.lib.config_parser import Config
from BTG.lib.io import module as mod


class Cache:
    def __init__(self, module_name, url, filename, search_method):
        self.config = Config.get_instance()
        self.module_name = module_name
        self.url = url
        self.filename = self.new_filename = filename
        self.temp_folder = "%s%s/" % (self.config["temporary_cache_path"], self.module_name)
        position = 0
        filename_copy = self.filename
        if not self.filename.isalnum():
            filename_copy = self.filename.replace("_", "")
            for pos, char in enumerate(filename_copy):
                if not char.isalnum() and char != '.':
                    position = pos
        self.new_filename = filename_copy[position:]
        self.temp_file = "%s%s" % (self.temp_folder, self.new_filename)

        self.createModuleFolder()
        if self.checkIfNotUpdate():
            if mod.allowedToSearch(search_method):
                self.downloadFile()
            else:
                raise NameError("Offline parameter is set on, cannot refresh outdated cache")
                return None
        self.content = self.getContent()

    def getContent(self):
        f = ""
        if exists(self.temp_file):
            try:
                f = open(self.temp_file, encoding="ISO-8859-1").read()
            except:
                f = open(self.temp_file).read()
        return f

    def downloadFile(self):
        """
            Get file from web
        """
        mod.display("%s.cache" % self.module_name,
                    message_type="DEBUG",
                    string="Update %s%s" % (self.url, self.filename))
        full_url = "%s%s" % (self.url, self.filename)
        try:
            r = requests.get(
                full_url,
                stream=True, headers=self.config["user_agent"],
                proxies=self.config["proxy_host"],
                timeout=self.config["requests_timeout"]
            )
        except ConnectionError as e:
            mod.display("%s.cache" % self.module_name,
                        message_type="ERROR",
                        string=e)
            return
        except ReadTimeout as e:
            mod.display("%s.cache" % self.module_name,
                        message_type="ERROR",
                        string="Timeout: %s" % (full_url))
            return
        except:
            raise
        if r.status_code == 200:
            if not exists("%s.lock" % self.temp_file):
                open("%s.lock" % self.temp_file, 'a').close()
                chmod("%s.lock" % self.temp_file, 0o666)
                if exists(self.temp_file):
                    to_chmod = False
                else:
                    to_chmod = True
                with open(self.temp_file, 'wb') as f:
                    for chunk in r:
                        f.write(chunk)
                if to_chmod:
                    chmod(self.temp_file, 0o666)
                try:
                    remove("%s.lock" % self.temp_file)
                except:
                    raise No_such_file('Race concurency between multiple instance of BTG, \
                                        cannot remove already deleted file')
        elif self.module_name == "malshare" and r.status.code == 404:
            # When we have a 404 from malshare it is a valid negative response
            raise malshare404('Hash not found on malshare, it is alright')
        else:
            mod.display("%s.cache" % self.module_name,
                        "ERROR",
                        "Response code: %s | %s" % (r.status_code, full_url))

    def checkIfNotUpdate(self):
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
                makedirs(self.config["temporary_cache_path"])
            except:
                mod.display("%s.cache" % self.module_name,
                            "FATAL_ERROR",
                            "Unable to create %s directory. (Permission denied)" % self.config["temporary_cache_path"])
                sys.exit()
            chmod(self.config["temporary_cache_path"], 0o770)
        if not isdir(self.temp_folder):
            mkdir(self.temp_folder)
            chmod(self.temp_folder, 0o770)
