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

import importlib
from lib.io import module as mod
from lib.config_parser import Config
config = Config.get_instance()

def module_worker(module, argument, type):
    """
        Load modules in python instance
    """
    mod.display(string="Load: %s/%s.py"%(config["modules_folder"], module))
    obj = importlib.import_module("modules."+module)
    for c in dir(obj):
        if module+"_enabled" in config:
            if module == c.lower() and config[module+"_enabled"]:
                attr = getattr(obj, c)(argument, type, config)
        else:
            mod.display("MAIN",
                        "INFO",
                        "Module : %s -- not configured" % (module))
