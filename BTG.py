#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2017 Conix Cybersecurity
# Copyright (c) 2016-2017 Lancelot Bogard
# Copyright (c) 2016-2017 Robin Marsollier
# Copyright (c) 2017 Alexandra Toussaint
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

import argparse
import importlib
import multiprocessing

import sys
from base64 import b64decode
from os import listdir, path, remove, kill, killpg, setsid, getpgid
from os.path import isfile, join, exists, abspath

import validators
from lib.io import module as mod
from lib.io import logSearch
from lib.run_module import module_worker

from urllib.parse import urlparse
import socket
import time

from rq import Connection, Queue
from redis import Redis
from config.redis_config import init_redis, init_queue, init_worker, number_of_worker

import subprocess
import signal

from config.config_parser import Config
config = Config.get_instance()
version = "1.b"     # BTG version

class BTG():
    """
        BTG Main class
    """
    def __init__(self, args):
        # Import modules
        if config["debug"]:
            ret = mod.display(string="Load modules from %s"%config["modules_folder"])
            print(ret)
        all_files = [f for f in listdir(config["modules_folder"]) if isfile(join(config["modules_folder"], f))]
        modules = []
        for file in all_files:
            if file[-3:] == ".py" and file[:-3] != "__init__":
                modules.append(file[:-3])

        global queue_going
        jobs = []
        tasks = []

        if args.file == "False" :
            for argument in args.observables:
                # TODO
                # Extending observables without doing an useless loop
                type = self.checkType(argument)
                if "split_observable" in config and config["split_observable"]:
                    if type == "URL":
                        self.extend_IOC(argument, args.observables)

                p = multiprocessing.Process(target=self.run,
                                            args=(argument,
                                                  type,
                                                  modules,
                                                  queue_going,
                                                  tasks))
                jobs.append(p)
                p.start()
        else :
            for file in args.observables :
                # TODO
                # Take care of big size file ?
                with open(file,"r") as f1 :
                    try:
                        observable_list = f1.read().strip().splitlines()
                        for argument in observable_list:
                            # TODO
                            # Extending observables without doing an useless loop
                            type = self.checkType(argument)
                            if "split_observable" in config and config["split_observable"]:
                                if type == "URL":
                                    self.extend_IOC(argument, observable_list)

                            p = multiprocessing.Process(target=self.run,
                                                        args=(argument,
                                                              type,
                                                              modules,
                                                              queue_going,
                                                              tasks))
                            jobs.append(p)
                            p.start()
                    except:
                        mod.display("MAIN",
                                    message_type="ERROR",
                                    string="Something went wrong with the argument file : %s" % f1)
                    finally:
                        f1.close()
                        print("All jobs are queued, everything went fine")


    async def resolver_DNS(domain):
        loop = asyncio.get_event_loop()
        # temp = resolver_DNS(domain)
        # IP = loop.run_until_complete(temp)
        resolver = aio.DNSResolver(loop=loop)
        return await resolver.query(domain, 'A')


    def extend_IOC(self, argument, observable_list):
        """
            Extending IOC from URL into URL + DOMAIN + IP
        """
        urlstruct = urlparse(argument)
        url = urlstruct.geturl()
        domain = urlstruct.netloc
        try:
            IP = socket.gethostbyname(domain)
        except:
            IP = None

        if domain not in observable_list:
            observable_list.append(domain)
        if not IP and IP not in observable_list:
            observable_list.append(IP)


    def run(self, argument, type, modules, q, tasks):
        """
            Main observable module requests
        """
        mod.display(ioc=argument, string="Observable type: %s"%type)
        if type is None:
            sys.exit()
        for module in modules:
            if module+"_enabled" in config and config[module+"_enabled"]:
                try :
                    task = queue_going.enqueue(module_worker,
                                    args=(module, argument, type),)
                    tasks.append(task)
                except :
                    mod.display("MAIN",
                                message_type="ERROR",
                                string="Could not connect enqueue the job : %s, %s, %s " % (module, argument, type))


    def checkType(self, argument):
        """
            Identify observable type
        """
        if not argument or len(argument.strip()) == 0:
            return None
        elif argument[0] is '#':
            return None
        elif validators.url(argument):
            return "URL"
        elif validators.md5(argument):
            return "MD5"
        elif validators.sha1(argument):
            return "SHA1"
        elif validators.sha256(argument):
            return "SHA256"
        elif validators.sha512(argument):
            return "SHA512"
        elif validators.ipv4(argument):
            return "IPv4"
        elif validators.ipv6(argument):
            return "IPv6"
        elif validators.domain(argument):
            return "domain"
        else:
            mod.display("MAIN",
                        argument,
                        "ERROR",
                        "Unable to retrieve observable type")
            return None


def motd():
    """
        Display Message Of The Day in console
    """
    motd = "%s v%s\n"%(b64decode("""
        ICAgIF9fX18gX19fX19fX19fX19fCiAgIC8gX18gKV8gIF9fLyBfX19fLwogIC8gX18gIHw\
        vIC8gLyAvIF9fICAKIC8gL18vIC8vIC8gLyAvXy8gLyAgCi9fX19fXy8vXy8gIFxfX19fLw\
        ==""".strip()).decode("utf-8"), version)
    print(motd.replace("\\n", "\n"))


def parse_args():
    """
        Define the arguments
    """
    parser = argparse.ArgumentParser(description='Observable to qualify')
    parser.add_argument('observables', metavar='observable', type=str, nargs='+',
                        help='Type: [URL,MD5,SHA1,SHA256,SHA512,IPv4,IPv6,domain] or a file containing one observable per line')
    parser.add_argument("-d", "--debug", action="store_true", help="Display debug informations",)
    parser.add_argument("-o", "--offline", action="store_true",
                        help=("Set BTG in offline mode, meaning all modules"
                              "described as online (i.e. VirusTotal) are deactivated"))
    parser.add_argument("-s", "--silent", action="store_true", help="Disable MOTD")
    return parser.parse_args()


def cleanups_lock_cache(real_path):
    for file in listdir(real_path):
        file_path = "%s%s/"%(real_path, file)
        if file.endswith(".lock"):
            mod.display("MAIN",
                        message_type="DEBUG",
                        string="Delete locked cache file: %s"%file_path[:-1])
            remove(file_path[:-1])
        else:
            if path.isdir(file_path):
                cleanups_lock_cache(file_path)


if __name__ == '__main__':
    args = parse_args()
    # Check if the parameter is a file or a list of observables
    if exists(args.observables[0]):
        args.file="True"
    else :
        args.file="False"
    # Check if debug
    if args.debug:
        config["debug"] = True
    if args.offline:
        config["offline"] = True
    dir_path = path.dirname(path.realpath(__file__))
    if "modules_folder" in config and "temporary_cache_path" in config:
        config["modules_folder"] = path.join(dir_path, config["modules_folder"])
        config["temporary_cache_path"] = path.join(dir_path, config["temporary_cache_path"])
    else:
        mod.display("MAIN",
                    message_type="ERROR",
                    string="Please check if you have modules_folder and temporary_cache_path \
                            field in config.ini")
    if config["display_motd"] and not args.silent:
        motd()
    try:
        if path.exists(config["temporary_cache_path"]):
            cleanups_lock_cache(config["temporary_cache_path"])
        logSearch(args)

        # subprocess loop to launch rq-worker
        processes = []
        max_worker = number_of_worker()
        for i in range(max_worker):
            processes.append(subprocess.Popen('python3 ./lib/run_worker.py', shell=True, preexec_fn = setsid))

        # Connecting to Redis
        redis_host, redis_port, redis_password = init_redis()
        if redis_host==None or redis_port==None:
            mod.display("MAIN",
                        message_type="ERROR",
                        string="Could not establish connection with Redis, check if you have redis_host, redis_port \
                                and maybe redis_password in /config/config.ini")
            sys.exit()
        with Connection(Redis(redis_host, redis_port, redis_password)) as conn:
                start_time = time.strftime('%X')
                queue_name = init_queue()
                queue_going = Queue(queue_name,connection=conn)
                BTG(args)

                # waiting for all jobs to be done
                while len(queue_going.jobs)>0 :
                    # print("BTG is processing ... %s -> %s" % (start_time,time.strftime('%X')), end='\r')
                    time.sleep(1)
                end_time = time.strftime('%X')

                # killing all subprocesses and their children
                time.sleep(3)
                for process in processes:
                    # killing all processes in the group
                    pgrp = getpgid(process.pid)
                    killpg(pgrp, signal.SIGINT)

                queue_going.delete(delete_jobs=True)
                print("\n All works done :", start_time, end_time)


    except (KeyboardInterrupt, SystemExit):
        '''
        Exit if user press CTRL+C
        '''
        print("\n")
        sys.exit()
