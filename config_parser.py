#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Alexandra Toussaint
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

import ast
import os
from ConfigParser import ConfigParser
from multiprocessing import Manager


class Config():

    __args = None

    @staticmethod
    def get_instance():
        if not Config.__args:
            Config.__args = Manager().dict()
            Config._parse_config()
            return Config.__args
        return Config.__args

    @staticmethod
    def _parse_config():
        conf = ConfigParser()
        dir_path = os.path.dirname(os.path.realpath(__file__))
        cfile="%s/config.ini"%dir_path
        if not os.path.isfile(cfile):
            print("BTG is not configured.\nPlease take care of config file : cp config.ini.editme config.ini; vim config.ini")
            exit(0)
        conf.read(cfile)
        Config.__args = {option: ast.literal_eval(conf.get(section, option)) for section in conf.sections() for option in conf.options(section)}
