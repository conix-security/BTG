#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2018 Tanguy Becam
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

import random
import redis
from os import getpid

from BTG.lib.config_parser import Config
from BTG.lib.utils import cluster

config = Config.get_instance()

# Full fill connection parameter for redis, see config/config.ini
def init_redis():
    redis_host, redis_port, redis_password = None, None, None
    if 'redis_host' in config and not config['redis_host'] == None :
        redis_host = config['redis_host']
    if 'redis_port' in config and not config['redis_port'] == None :
        redis_port = config['redis_port']
    if 'redis_password' in config:
        redis_password = config['redis_password']
    return redis_host, redis_port, redis_password

def init_variables(redis_host, redis_port, redis_password, fp):
    r = redis.StrictRedis(host=redis_host, port=redis_port, password=redis_password)
    # Producing a random name for global variables : queues, lock, dict,
    # thus we can run multiple instance of BTG
    random.seed()
    hash = hex(random.getrandbits(32))
    cond = True
    while cond:
        temp = r.get(hash)
        if temp is not None:
            hash = hex(random.getrandbits(32))
            continue
        else:
            cond = False
            for i in range(1,2):
                temp = r.get(hex(int(hash, base=16) + i))
                if temp is not None:
                    hash = hex(random.getrandbits(32))
                    cond = True
                    break
    working_queue = hex(int(hash, base=16) + 1)
    request_queue = hex(int(hash, base=16) + 2)
    lockname, dictname = cluster.get_keys(fp)
    return working_queue, request_queue, lockname, dictname

# Specifying worker options : [burst, logging_level]
def init_worker():
    burst = False
    logging_level = "ERROR"
    return burst, logging_level

# Number of worker to launch
def number_of_worker():
    if 'max_worker' in config and config['max_worker'] > 0:
        max_worker = config['max_worker']
    else:
        max_worker = 4
    return max_worker
