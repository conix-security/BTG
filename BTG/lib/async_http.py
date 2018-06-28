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

import asyncio
from aiohttp import ClientSession, BasicAuth
import redis
from redis import Redis
from rq import Connection, Queue, Worker
import re
import json
from itertools import groupby

from BTG.lib.worker_tasks import module_worker_response
from BTG.lib.io import module as mod
from BTG.lib.redis_config import init_redis
from BTG.lib.config_parser import Config

config = Config.get_instance()
# --------------------------------------------------------------------------- #
#               Storage
# --------------------------------------------------------------------------- #

# In both following function, we are not using rq queue, because we are storing
# raw data rq only take care of function stored as job

# Pushing request:(url, module_name) into a redis_list
def store_request(queues, request):
    queue_1 = queues[0]
    queue_2 = queues[1]
    redis_host, redis_port, redis_password = init_redis()
    try:
        r = redis.StrictRedis(host=redis_host, port=redis_port,
                              password=redis_password, db=0)
    except:
        mod.display("ASYNC_HTTP",
                    message_type="ERROR",
                    string="Could not establish connection with Redis in func store_request")
    try:
        r.rpush(queue_2, request)
    except:
        mod.display("ASYNC_HTTP",
                    message_type="ERROR",
                    string="Cannot push request: %s to Redis\
                    on queue: %s" % (request[0], queue))

def pollout_requests(queue_2, nb_to_do):
    redis_host, redis_port, redis_password = init_redis()
    try:
        r = redis.StrictRedis(host=redis_host, port=redis_port,
                              password=redis_password, db=0)
    except:
        mod.display("ASYNC_HTTP",
                    message_type="ERROR",
                    string="Cannot establish connection with Redis in func pollout_requests")
    requests = []
    while len(requests) < nb_to_do:
        request = r.lpop(queue_2)
        if request is None:
            break
        else:
            request = parse_redis_string(request)
            if request is not None:
                requests.append(request)
    return requests

# Because redis storage type isn't python-like
def parse_redis_string(string):
    # quoted = re.compile("[^']*")
    request = string.decode("utf_8")
    try:
        request = json.loads(request)
    except:
        request = None
    return request

# --------------------------------------------------------------------------- #
#               The following is managing the HTTP requests
# --------------------------------------------------------------------------- #

# code from aiohttp.readthedocs.io
async def fetch_get(url, session, headers, proxy, module, ioc, timeout, auth, server_id, verify):
    try:
        async with session.get(url, headers=headers, proxy=proxy,
                               timeout=timeout, auth=auth, ssl=verify) as response:
            return await response.text(), response.status, module, ioc, server_id
    except:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="Failed to connect to %s, server was probably too slow and request has been dropped out" % (url))

async def fetch_post(url, session, headers, proxy, data, module, ioc, timeout, auth, server_id, verify):
    try:
        async with session.post(url, data=data, headers=headers, proxy=proxy,
                                timeout=timeout, auth=auth, ssl=verify) as response:
            return await response.text(), response.status, module, ioc, server_id
    except:
        mod.display(module,
                    ioc,
                    message_type="ERROR",
                    string="Failed to connect to %s" % (url))

def filler(request):
    url = request['url']
    module_name = request['module']
    ioc = request['ioc']
    verbose = request['verbose']
    headers = request['headers']

    if request['proxy']['https'] == '':
        if request['proxy']['http'] == '':
            proxy = None
        else:
            proxy = request['proxy']['http']
    else:
        proxy = request['proxy']['https']

    if 'auth' in request:
        type = request['auth'][0]
        # TODO
        # add other condition if any
        if type == "BASIC":
            auth = BasicAuth(request['auth'][1][0],request['auth'][1][1])
        else:
            auth = None
    else:
        auth = None

    if module_name in ['cuckoosandbox', 'viper', 'misp']:
        server_id = request['server_id']
    else:
        server_id = None

    if 'verify' in request:
        verify = request['verify']
    else:
        verify = None

    return url,module_name,ioc,verbose,headers,proxy,auth,server_id,verify

async def bound_fetch(sem, session, request, timeout):
    url,module_name,ioc,verbose,headers,proxy,auth,server_id,verify = filler(request)
    if verbose == "GET":
        # Getter function with semaphore.
        async with sem:
            return await fetch_get(url, session, headers, proxy,
                                   module_name, ioc, timeout, auth, server_id, verify)
    elif verbose == "POST":
        data = request['data']
        # Getter function with semaphore.
        async with sem:
            return await fetch_post(url, session, headers, proxy, data,
                                    module_name, ioc, timeout, auth, server_id, verify)
    else:
        mod.display(module_name,
                    ioc,
                    message_type="ERROR",
                    string="Associated HTTP verbose for %s, is neither GET nor POST" % (url))

async def run(requests):
    tasks = []

    if 'requests_timeout' in config:
        timeout = config['requests_timeout']
    else:
        timeout = 10

    # create instance of Semaphore
    sem = asyncio.Semaphore(len(requests))
    # Create client session that will ensure we dont open new connection
    # per each request.
    async with ClientSession() as session:
        for request in requests:
            # pass Semaphore and session to every GET request
            task = asyncio.ensure_future(bound_fetch(sem, session, request, timeout))
            tasks.append(task)
        responses = asyncio.gather(*tasks)
        return await responses

def request_poller(queue_1, queue_2, nb_to_do):
    requests = pollout_requests(queue_2, nb_to_do)
    try:
        with Connection(Redis()) as conn:
            q = Queue(queue_1, connection=conn)
    except:
        mod.display("ASYNC_HTTP",
                    message_type="ERROR",
                    string="Could not establish connection with Redis, check if you have redis_host, \
                    redis_port and maybe redis_password in /config/config.ini")

    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(run(requests))
    x = loop.run_until_complete(future)
    loop.close()
    for y in x:
        if y is not None:
            try:
                job = q.enqueue(module_worker_response, args=(y) ,result_ttl=0)
            except:
                mod.display("ASYNC_HTTP",
                            message_type="ERROR",
                            string="Could not enqueue job to Redis in func request_poller")
