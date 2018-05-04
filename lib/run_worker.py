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

from lib.io import module as mod
from rq import Connection, Queue, Worker
from redis import Redis

from config.redis_config import init_redis, init_queue, init_worker

if __name__ == '__main__':
    # Connecting to Redis
    redis_host, redis_port, redis_password = init_redis()
    with Connection(Redis(redis_host, redis_port, redis_password)) as conn:
        queue_name = sys.argv[1]
        q = Queue(queue_name, connection=conn)
        mod.display("WORKER",
                    message_type="INFO",
                    string="max_process either the field or the value of the field is not there")

        burst, logging_level = init_worker()
        worker = Worker(q).work(burst=burst, logging_level=logging_level)
