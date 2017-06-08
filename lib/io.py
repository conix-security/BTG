#!/usr/bin/python
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


from datetime import datetime
from os import chmod
from os.path import exists
from platform import system

from config_parser import Config


class module:
    """
        This function display prettily informations
    """
    def __init__(self):
        return None

    @classmethod
    def display(self, module="INIT", ioc="", message_type="DEBUG", string=""):
        exec('colorize = colors.%s'%message_type)
        config = Config.get_instance()
        if not config["debug"] and (message_type == "INFO" or message_type == "DEBUG"):
            pass
        else:
            if ioc != "":
                if len(ioc) >= 67:
                    ioc = '%s%s...'%(ioc[:64], colors.NORMAL)
                ioc_show = "{%s%s%s} "%(colors.INFO, ioc, colors.NORMAL)
            else:
                ioc_show = " "
            output = "[%s][%s%s%s]%s%s%s%s"%(module,
                                             colorize,
                                             message_type,
                                             colors.NORMAL,
                                             ioc_show,
                                             colors.BOLD,
                                             string,
                                             colors.NORMAL)
            if message_type == "FOUND":
                if not exists(config["log_found_file"]):
                    open(config["log_found_file"], 'a').close()
                    chmod(config["log_found_file"], 0o777)
                f = open(config["log_found_file"], 'a')
                f.write("%s%s\n"%(datetime.now().strftime('[%d-%m-%Y %H:%M:%S]'), output))
                f.close()
            print(output)

    @classmethod
    def allowedToSearch(self, status):
        config = Config.get_instance()
        """
            Input: "Online", "Onpremises"
        """
        if status == "Onpremises":
            '''
            here the modules claims to be related to an on premises service
            , i.e. being inside researcher nertwork, so we allow the lookup

            modules: misp, cuckoo
            '''
            return True
        elif status == "Online" and not config["offline"]:
            '''
            the modules claims to be online, and user _do not_ asked the
            lookup to be performed offline
            thus it is allowed to perform if online
            '''
            return True
        '''
        if none of previous case, lookup forbidden
        '''
        return False

        '''
        possible refactoring :
        if config[offline]:
            if status = onpremises
                true
            if status = cache
                true
            if status = online
                false
        else:
            true
        '''


class logSearch:
    def __init__(self, iocs):
        config = Config.get_instance()
        if not exists(config["log_search_file"]):
            open(config["log_search_file"], 'a').close()
            chmod(config["log_search_file"], 0o777)
        f = open(config["log_search_file"], 'a')
        for ioc in iocs:
            f.write("%s %s\n"%(datetime.now().strftime('[%d-%m-%Y %H:%M:%S]'), ioc))
        f.close()


class colors:
    config = Config.get_instance()
    if system() == "Windows" or config["terminal_color"] is False:
        DEBUG = ''
        INFO = ''
        FOUND = ''
        WARNING = ''
        ERROR = ''
        NORMAL = ''
        BOLD = ''
    else:
        DEBUG = '\033[95m'
        INFO = '\033[94m'
        FOUND = '\033[92m'
        WARNING = '\033[93m'
        ERROR = '\033[91m'
        NORMAL = '\033[0m'
        BOLD = '\033[1m'
