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

import sys, os
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from config.config_parser import Config
config = Config.get_instance()

# Full fill connection parameter for redis, see config/config.ini
def init_redis():
    redis_host, redis_port, redis_password = None, None, None
    if 'redis_host' in config and not config['redis_host']==None :
        redis_host = config['redis_host']
    if 'redis_port' in config and not config['redis_port']==None :
        redis_port = config['redis_port']
    if 'redis_password' in config:
        redis_password = config['redis_password']
    return redis_host, redis_port, redis_password

# Specifying Queue options : [name, timeout, ttl, ...]
def init_queue():
    queue_name = 'default'
    # queue_ttl = None
    # queue_timeout = None
    # queue_result_timeout = None
    return queue_name
    # return queue_name, queue_ttl, queue_timeout, queue_result_timeout

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
