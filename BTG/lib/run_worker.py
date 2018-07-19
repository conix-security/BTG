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

from redis import Redis
from rq import Connection, Queue, Worker
import sys

from BTG.lib.redis_config import init_redis, init_worker


if __name__ == '__main__':
    # Connecting to Redis
    redis_host, redis_port, redis_password = init_redis()
    with Connection(Redis(redis_host, redis_port, redis_password)) as conn:
        queue_name = sys.argv[1]
        q = Queue(queue_name, connection=conn)
        burst, logging_level = init_worker()
        worker = Worker(q).work(burst=burst, logging_level=logging_level)
