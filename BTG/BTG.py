#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2016-2018 Conix Cybersecurity
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

import sys
from os import listdir, path, remove, kill, killpg, setsid, getpgid, mkdir, chmod, makedirs
from os.path import isfile, join, exists, abspath, isdir, dirname
from base64 import b64decode
import argparse
import importlib
import re
import tldextract
import time
from datetime import datetime
from rq import Connection, Queue, Worker
import redis
from redis import Redis
import subprocess
import signal
import validators

from BTG.lib.io import module as mod
from BTG.lib.io import logSearch
from BTG.lib.io import errors as err
from BTG.lib.io import colors
from BTG.lib.worker_tasks import module_worker_request
from BTG.lib.redis_config import init_redis, init_queue, init_worker, number_of_worker
from BTG.lib.config_parser import Config

config = Config.get_instance()
version = "2.0"     # BTG version

class BTG():
    """
        BTG Main class
    """
    def __init__(self, args, modules):
        # Import modules
        if config["debug"]:
            ret = mod.display(string="Load modules from %s"%config["modules_folder"])

        jobs = []
        tasks = []
        queues = [working_queue, request_queue]

        if args.file == "False" :
            for argument in args.observables:
                type = self.checkType(argument)
                if "split_observable" in config and config["split_observable"]:
                    if type == "URL":
                        self.extend_IOC(argument, observable_list)

                self.run(argument,type,modules,tasks,queues)
        else :
            for file in args.observables :
                with open(file,"r") as f1 :
                    try:
                        observable_list = f1.read().strip().splitlines()
                    except:
                        mod.display("MAIN",
                                    message_type="FATAL_ERROR",
                                    string="Something went wrong with the argument file")
                    finally:
                        f1.close()
                for argument in observable_list:
                    type = self.checkType(argument)
                    if "split_observable" in config and config["split_observable"]:
                        if type == "URL":
                            self.extend_IOC(argument, observable_list)
                    self.run(argument,type,modules,tasks,queues)


    def extend_IOC(self, argument, observable_list):
        """
            Extending IOC from URL into URL + DOMAIN + IP
        """
        if config['offline']:
            # Cache search
            if "TLDE_cache" in config:
                cache_extract = tldextract.TLDExtract(cache_file=config['TLDE_cache'])
                extract = cache_extract(argument)
        else:
            # Live search
            extract = tldextract.extract(argument)

        try:
            registered_domain = extract.registered_domain
        except:
            registered_domain = None
        try:
            suffix_domain = extract.suffix
        except:
            suffix_domain = None
        try:
            complete_domain = '.'.join(part for part in extract if part)
        except:
            complete_domain = None
        domains =[registered_domain, suffix_domain, complete_domain]

        IPs = [None, None, None]
        if not "offline" in config:
            for domain in domains:
                try:
                    IP = socket.gethostbyname(domain)
                except:
                    IP = None
                IPs.append(IP)

        for domain in domains:
            if domain is not None and domain not in observable_list:
                observable_list.append(domain)
        for IP in IPs:
            if IP is not None and IP not in observable_list:
                observable_list.append(IP)


    def run(self, argument, type, modules, tasks, queues):
        """
            Main observable module requests
        """
        mod.display(ioc=argument, string="Observable type: %s"%type)
        if type is None:
            mod.display("MAIN",
                        message_type="WARNING",
                        string="IOC : %s has an undefined type : %s" % (argument, type))
            return None
        for module in modules:
            if module+"_enabled" in config and config[module+"_enabled"]:
                try :
                    task = working_going.enqueue(module_worker_request,
                                    args=(module, argument, type, queues),result_ttl=0)
                    tasks.append(task)
                except :
                    mod.display("MAIN",
                                message_type="FATAL_ERROR",
                                string="Could not enqueue the job : %s, %s, %s " % (module, argument, type))


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
            return None


class Utils:
    def __init__():
        return None

    #List all modules
    def gen_module_list():
        all_files = [f for f in listdir(config["modules_folder"]) if isfile(join(config["modules_folder"], f))]
        modules = []
        for file in all_files:
            if file[-3:] == ".py" and file[:-3] != "__init__":
                modules.append(file[:-3])
        return modules

    # List all activated modules
    def gen_enabled_modules_list(modules):
        enabled_list = []
        for module in modules:
            if module+"_enabled" in config and config[module+"_enabled"]:
                enabled_list.append(module)
        return enabled_list

    # Count errors encountered during execution
    def show_up_errors(start_time, end_time, modules):
        enabled_list = Utils.gen_enabled_modules_list(modules)
        dict_list = []
        for module in enabled_list:
            dict_list.append({"module_name" : module, "nb_error" : 0})
        log_error_file = config["log_folder"] + config["log_error_file"]
        try:
            with open(log_error_file,"r") as f :
                try:
                    lines = f.read().strip().splitlines()
                except:
                    mod.display("MAIN",
                                message_type="FATAL_ERROR",
                                string="Could not open the log_error_file, checkout your btg.cfg.")
                finally:
                    f.close()
        except:
            return dict_list

        regex = re.compile("(?<=\[).*?(?=\])")
        for line in lines :
            match = regex.findall(line)
            log_time = match[0]
            log_module = match[1]
            if log_time >= start_time and log_time <= end_time:
                for dict in dict_list:
                    if log_module == dict['module_name']:
                        dict["nb_error"] = dict["nb_error"] + 1
        return dict_list


    def motd():
        """
            Display Message Of The Day in console
        """
        motd = "%s v%s\n"%(b64decode("""
            ICAgIF9fX18gX19fX19fX19fX19fCiAgIC8gX18gKV8gIF9fLyBfX19fLwogIC8gX18gIHw\
            vIC8gLyAvIF9fICAKIC8gL18vIC8vIC8gLyAvXy8gLyAgCi9fX19fXy8vXy8gIFxfX19fLw\
            ==""".strip()).decode("utf-8"), version)
        print(motd.replace("\\n", "\n"))


    def createLoggingFolder():
        if not isdir(config["log_folder"]):
            try:
                makedirs(config["log_folder"])
            except:
                mod.display("MAIN",
                            message_type="FATAL_ERROR",
                            string="Unable to create %s directory. (Permission denied)"%config["log_folder"])
                sys.exit()
            chmod(config["log_folder"], 0o777)


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
                    Utils.cleanups_lock_cache(file_path)


    def graceful_shutdown(working_going):
        # DO-WHILE loop to check if a worker is still working
        is_busy = True
        while is_busy:
            states = []
            workers = Worker.all(queue=working_going)
            for worker in workers:
                state = worker.get_state()
                states.append(state)
            for state in states:
                if state == 'busy':
                    break
                is_busy = False
            time.sleep(1)
        time.sleep(1)

    def shut_down(processes, working_going, failed_queue, sig_int=True):
        if not sig_int:
            Utils.graceful_shutdown(working_going)

        # Removing undone jobs
        working_going.delete(delete_jobs=True)
        # Killing all processes in the group
        for process in processes:
            pgrp = getpgid(process.pid)
            killpg(pgrp, signal.SIGTERM)
        time.sleep(2)
        # Clearing potentially failed jobs because of the previous kill
        # TODO
        # Those should have been timed out, can we log them before clearing queue ?
        failed_queue.empty()


    def subprocess_launcher():
        """
            Subprocess loop to launch rq-worker
        """
        processes = []
        max_worker = number_of_worker()
        worker_path = dirname(__file__)+'/lib/run_worker.py '
        poller_path = dirname(__file__)+'/lib/poller.py '
        try :
            for i in range(max_worker):
                processes.append(subprocess.Popen(['python3 '+ worker_path + working_queue], shell=True, preexec_fn = setsid))
            processes.append(subprocess.Popen(['python3 '+ poller_path + working_queue +' '+ request_queue], shell=True, preexec_fn = setsid))
        except :
            mod.display("MAIN",
                        message_type="FATAL_ERROR",
                        string="Could not launch workers as subprocess")
            sys.exit()

        return processes


def main(argv=None):
    args = Utils.parse_args()
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
    if "modules_folder" in config and "temporary_cache_path" in config and "log_folder" in config:
        config["log_folder"] = path.join(dir_path, config["log_folder"])
        config["modules_folder"] = path.join(dir_path, config["modules_folder"])
        config["temporary_cache_path"] = path.join(dir_path, config["temporary_cache_path"])
    else:
        mod.display("MAIN",
                    message_type="FATAL_ERROR",
                    string="Please check if you have log_folder, modules_folder and temporary_cache_path \
                            field in btg.cfg")
    if config["display_motd"] and not args.silent:
        Utils.motd()

    global working_queue, working_going, request_queue, failed_queue
    try:
        Utils.createLoggingFolder()
        if path.exists(config["temporary_cache_path"]):
            Utils.cleanups_lock_cache(config["temporary_cache_path"])
        logSearch(args)
        # Connecting to Redis
        redis_host, redis_port, redis_password = init_redis()
        try :
            with Connection(Redis(redis_host, redis_port, redis_password)) as conn:
                working_queue, request_queue = init_queue(redis_host, redis_port, redis_password)
                working_going = Queue(working_queue, connection=conn)
                failed_queue = Queue('failed', connection=conn)
            r = redis.StrictRedis(host=redis_host, port=redis_port,
                                  password=redis_password)
        except :
            mod.display("MAIN",
                        message_type="FATAL_ERROR",
                        string="Could not establish connection with Redis, check if you have redis_host, redis_port and maybe redis_password in /config/btg.cfg")
            sys.exit()

        processes = Utils.subprocess_launcher()
        modules = Utils.gen_module_list()
        start_time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
        BTG(args, modules)
        # waiting for all jobs to be done
        while True:
            if len(working_going.jobs) == 0 and r.llen(request_queue) == 0:
                break;
            time.sleep(1)

        try:
            Utils.shut_down(processes, working_going, failed_queue, sig_int=False)
        except:
            mod.display("MAIN",
                        message_type="FATAL_ERROR",
                        string="Could not close subprocesses, maybe there were not any to begin with.")
            sys.exit()
        end_time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
        errors_to_display = Utils.show_up_errors(start_time, end_time, modules)
        err.display(dict_list=errors_to_display)
        print("\n%sAll works done :\n   from %s to %s%s" % (colors.FOUND, start_time, end_time, colors.NORMAL))
    except (KeyboardInterrupt, SystemExit):
        '''
        Exit if user press CTRL+C
        '''
        time.sleep(2)
        print("\n%s%sA FATAL_ERROR occured or you pressed CTRL+C" % (colors.BOLD, colors.FATAL_ERROR))
        print("Closing the worker, and clearing pending jobs ...%s\n" % (colors.NORMAL))

        try:
            Utils.shut_down(processes, working_going, failed_queue)
        except:
            mod.display("MAIN",
                        message_type="FATAL_ERROR",
                        string="Could not close subprocesses, maybe there were not any to begin with.")
            sys.exit()

        sys.exit()
