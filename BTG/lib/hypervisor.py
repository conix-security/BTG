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

from redis import Redis
from rq import Connection, Queue
import os
import redis
import signal
import sys
import time

from BTG.lib.io import colors
from BTG.lib.io import module as mod
from BTG.lib.redis_config import init_redis
from BTG.lib.utils import redis_utils, cluster


class supervisor:
    def __init__():
        return None

    # Check if dad is alive
    def check_pid(pid):
        if pid < 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False  # No such process
        except PermissionError:
            return True  # Operation not permitted (i.e., process exists)
        else:
            return True  # no error, we can send a signal to the process

    def observe_parent_process(main_pid, subprocesses_pid, pf, redis_conn,
                               working_going, failed_queue,
                               lockname, dictname):
        starttime = time.time()
        while supervisor.check_pid(main_pid):
            time.sleep(1.0 - ((time.time() - starttime) % 1.0))

        # Dad is dead, we must kill subprocesses and remove pidfile
        print("\n%s%sBTG main process encountered an unexpected error" % (colors.BOLD, colors.FATAL_ERROR))
        print("Closing the worker, and clearing pending jobs ...%s\n" % (colors.NORMAL))
        try:
            redis_utils.shutdown(subprocesses_pid, working_going, failed_queue,
                                 lockname, dictname,
                                 redis_conn, sig_int=False)
        except:
            mod.display("HYPERVISOR",
                        "FATAL_ERROR",
                        "Could not close subprocesses, here are their pid :"+"".join(['%s ' % i for i in subprocesses_pid]))

        try:
            os.remove(pf)
        except FileNotFoundError:
            pass
        except:
            mod.display("HYPERVISOR",
                        "FATAL_ERROR",
                        "Could not delete %s, make sure to delete it for next usage" % pf)
        sys.exit()


if __name__ == '__main__':
    try:
        main_pid = int(sys.argv[1])
        pf = sys.argv[2]
        working_queue = sys.argv[3]
        subprocesses_pid = sys.argv[4:]

        redis_host, redis_port, redis_password = init_redis()
        try:
            with Connection(Redis(redis_host, redis_port, redis_password)) as conn:
                working_going = Queue(working_queue, connection=conn)
                failed_queue = Queue('failed', connection=conn)
            redis_conn = redis.StrictRedis(host=redis_host, port=redis_port,
                                           password=redis_password)
        except:
            mod.display("HYPERVISOR",
                        "FATAL_ERROR",
                        "Could not establish connection with Redis, check if you have redis_host, redis_port and maybe redis_password in /config/btg.cfg")
            os.killpg(main_pid, signal.SIGTERM)

        lockname, dictname = cluster.get_keys(pf)
        supervisor.observe_parent_process(main_pid, subprocesses_pid, pf,
                                          redis_conn, working_going,
                                          failed_queue, lockname, dictname)
    except (KeyboardInterrupt, SystemExit):
        try:
            os.killpg(main_pid, signal.SIGTERM)
        except:
            pass
        print("%sEverything is cleared, BTG is terminated\n%s" % (colors.FOUND, colors.NORMAL))
