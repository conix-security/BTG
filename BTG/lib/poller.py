#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2018 Conix Cybersecurity
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
import time
import redis
from redis import Redis
from rq import Connection, Queue

import BTG.lib.async_http as async_http
from BTG.lib.redis_config import init_redis
from BTG.lib.io import module as mod

# --------------------------------------------------------------------------- #
#               Time Based Poller
# --------------------------------------------------------------------------- #


class poller:
    def __init__():
        return None

    def time_based_poller(working_queue, request_queue):
        starttime = time.time()
        queue_1 = working_queue
        queue_2 = request_queue

        while True:
            redis_host, redis_port, redis_password = init_redis()
            try:
                r = redis.StrictRedis(host=redis_host, port=redis_port,
                                      password=redis_password)
            except:
                mod.display("POLLER",
                            message_type="ERROR",
                            string="Cannot establish connection with Redis in func time_based_poller")
            try:
                len = r.llen(queue_2)
            except:
                mod.display("POLLER",
                            message_type="ERROR",
                            string="Cannot ask queue: %s length to Redis" % (queue_2))

            if len <= 0:
                time.sleep(1.0 - ((time.time() - starttime) % 1.0))
                continue
            try:
                with Connection(Redis()) as conn:
                    q = Queue(queue_1, connection=conn)
                q.enqueue(async_http.request_poller,
                          args=(queue_1, queue_2, len), result_ttl=0)
            except:
                mod.display("POLLER",
                            message_type="ERROR",
                            string="Could not establish connection with Redis, check if you have redis_host, \
                            redis_port and maybe redis_password in /config/config.ini")
            time.sleep(1.0 - ((time.time() - starttime) % 1.0))


if __name__ == '__main__':
    working_queue = sys.argv[1]
    request_queue = sys.argv[2]
    try:
        poller.time_based_poller(working_queue, request_queue)
    except (KeyboardInterrupt, SystemExit):
        sys.exit()
