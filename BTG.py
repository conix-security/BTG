#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2017 Conix Cybersecurity
# Copyright (c) 2016-2017 Lancelot Bogard
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


version = "1.1" # BTG version

# Import python modules
from lib.io import display, logSearch
from lib.argument_parse import parse
try:
    import sys
    import validators
    import multiprocessing
    import argparse
    from re import findall
    from os import listdir, path, remove
    from os.path import isfile, join
    from platform import system
    from base64 import b64decode
    from time import sleep
    if system() == "Windows":
        import win_inet_pton
except:
    print "[ERROR] Please install externals modules from 'requirements.txt': pip install -r requirements.txt"
    exit()

from config_parser import Config
import importlib

config = Config.get_instance()

class BTG:
    """
        BTG Main class
    """
    def __init__(self, args):

        # Import modules
        if config["debug"]:
            display(string="Load modules from %s"%config["modules_folder"])
        all_files = [f for f in listdir(config["modules_folder"]) if isfile(join(config["modules_folder"], f))]
        modules = []
        for file in all_files:
            if file[-3:] == ".py" and file[:-3] != "__init__":                
                modules.append(file[:-3])
        jobs = []
        # Start BTG process
        i = 0
        for argument in args:
            i+=1
            p = multiprocessing.Process(target=self.run, args=(argument, modules,))
            if "max_process" in config :
                while len(jobs) > config["max_process"]:
                    for job in jobs:
                        if not job.is_alive():
                            jobs.remove(job)
                        else:
                            sleep(3)
            else :
                display(message_type="ERROR", string="Please check if you have max_process field in config.ini")
            jobs.append(p)
            p.start()

    def run(self, argument, modules):
        """
            Main ioc module requests
        """
        type = self.checkType(argument)
        display(ioc=argument, string="IOC type: %s"%type)
        if type == None:
            sys.exit()
        workers = []
        for module in modules:
            worker = multiprocessing.Process(target = self.module_worker, 
                args = (module, argument, type,))
            workers.append(worker)
            worker.start()

    def module_worker(self, module, argument, type):
        """
            Load modules in python instance
        """
        display(string="Load: %s/%s.py"%(config["modules_folder"], module))
        obj = importlib.import_module("modules."+module)
        for c in dir(obj):
            if module+"_enabled" in config :
                if module == c.lower() and config[module+"_enabled"]:
                    getattr(obj, c)(argument,type,config)

    def checkType(self, argument):
        """
            Identify IOC type
        """
        if validators.url(argument):
            return "URL"
        elif len(findall(r"^([a-fA-F\d]{32}$)", argument)):
            return "MD5"
        elif len(findall(r"^[0-9a-f]{5,40}$", argument)):
            return "SHA1"
        elif len(findall(r"^[A-Fa-f0-9]{64}$", argument)):
            return "SHA256"
        elif len(findall(r"^\w{128}$", argument)):
            return "SHA512"
        elif validators.ipv4(argument):
            return "IPv4"
        elif validators.ipv6(argument):
            return "IPv6"
        elif len(findall(r"^(?=.{4,255}$)([a-zA-Z0-9][a-zA-Z0-9-]{,61}[a-zA-Z0-9]\.)+[a-zA-Z0-9]{2,5}$", argument)) or parse.is_valid_domain(argument):
            return "domain"
        else:
            display("MAIN", argument, "ERROR", "Unable to retrieve IOC type")
            return None

    @classmethod
    def allowedToSearch(self, status):
        """
            Input: "Online", "Offline"
        """
        if status == "Offline":
            return True
        elif status == "Online" and not config["offline"]:
            return True
        return False

def motd():
    """
        Display Message Of The Day in console
    """
    print "%s v%s\n"%(b64decode("""
        ICAgIF9fX18gX19fX19fX19fX19fCiAgIC8gX18gKV8gIF9fLyBfX19fLwogIC8gX18gIHw\
        vIC8gLyAvIF9fICAKIC8gL18vIC8vIC8gLyAvXy8gLyAgCi9fX19fXy8vXy8gIFxfX19fLw\
        ==""".strip()), version)

def parse_args():
    """
        Define the arguments
    """
    parser = argparse.ArgumentParser(description='IOC to search')
    parser.add_argument('iocs', metavar='IOC', type=str, nargs='+',
                        help='Type: [URL,MD5,SHA1,SHA256,SHA512,IPv4,IPv6,domain]')
    parser.add_argument("-d", "--debug", action="store_true", help="Display debug informations",)
    parser.add_argument("-o", "--offline", action="store_true", help="Set BTG in offline mode")
    parser.add_argument("-s", "--silent", action="store_true", help="Disable MOTD")
    return parser.parse_args()

def cleanups_lock_cache(real_path):
    for file in listdir(real_path):
        file_path = "%s%s/"%(real_path, file)
        if file.endswith(".lock"):
            display("MAIN", message_type="DEBUG", string="Delete locked cache file: %s"%file_path[:-1])
            remove(file_path[:-1])
        else:
            if path.isdir(file_path):
                cleanups_lock_cache(file_path)

if __name__ == '__main__':

    args = parse_args()
    # Check if debug
    if args.debug:
        config["debug"] = True
    if args.offline:
        config["offline"] = True
    dir_path = path.dirname(path.realpath(__file__))
    if "modules_folder" in config and "temporary_cache_path" in config:
        config["modules_folder"] = path.join(dir_path, config["modules_folder"])
        config["temporary_cache_path"] = path.join(dir_path, config["temporary_cache_path"])
    else :
        display(message_type="ERROR", string="Please check if you have modules_folder and temporary_cache_path field in config.ini")
    if config["display_motd"] and not args.silent:
        motd()
    try:
        if path.exists(config["temporary_cache_path"]):
            cleanups_lock_cache(config["temporary_cache_path"])
        logSearch(args.iocs)
        BTG(args.iocs)
    except (KeyboardInterrupt, SystemExit):
        # Exit if user press CTRL+C
        print "\n"
        sys.exit()

