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

import redis
import json
import re
import time
import uuid
from os import getpid

class cluster:

    def __init__():
        return None

    def set_keys(k1, k2):
        global lockname
        global dictname
        lockname = k1
        dictname = k2

    def acquire_lock(conn, lockname):
        id = str(uuid.uuid4())
        while True:
            if conn.setnx(lockname, id):
                return id
            time.sleep(0.5)
        return False

    def release_lock(conn, lockname, id):
        while True:
            value = conn.get(lockname).decode("utf-8")
            if value == id:
                conn.delete(lockname)
                return True
            time.sleep(0.5)

    def add_cluster(ioc, modules, dictname, conn):
        cluster = {'ioc':ioc,
                   'modules':modules,
                   'nb_module':len(modules),
                   'messages':[]
                   }
        conn.lpush(dictname, json.dumps(cluster))

    def edit_cluster(ioc, module, message, conn, lockname, dictname):
        c = None
        locked = cluster.acquire_lock(conn, lockname)
        # print('locked')
        bytes_clusters = conn.lrange(dictname, 0, -1)

        for bytes_cluster in bytes_clusters:
            c = json.loads(bytes_cluster.decode("utf-8"))
            if c['ioc'] == ioc and module in c['modules']:
                c['nb_module'] = c['nb_module']-1
                c['messages'].append(message)
                conn.lrem(dictname, 1, bytes_cluster)
                json_cluster = json.dumps(c)
                conn.lpush(dictname, json.dumps(c))
                break
            else:
                c = None
        unlocked = cluster.release_lock(conn, lockname, locked)
        # print('unlocked\n\n')
        return c

    def print_cluster(cluster, conn):
        if not cluster:
            return None
        if len(cluster['modules'])==len(cluster['messages']) and cluster['nb_module']==0:
            for message in cluster['messages']:
                print(message)
            print('')
            # remove_cluster(cluster['ioc'], conn)

    # def remove_cluster(ioc, conn):
    #     clusters = conn.lrange('clusters', 0, -1)
    #     for cluster in clusters:
    #         if cluster['ioc'] == ioc:
    #             try:
    #                 conn.lrem('clusters', dict)
    #             except Exception as e:
    #                 print(e)
