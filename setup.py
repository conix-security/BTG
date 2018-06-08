#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2018 Conix Cybersecurity
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

import setuptools
import os

setuptools.setup(
    name="BTG",
    packages=["BTG"],
    version="2.0",
    author="Conix Security",
    author_email="robin.marsollier@conix.fr",
    description="This tool allows you to qualify one or more potential malicious observables of various type (URL, MD5, SHA1, SHA256, SHA512, IPv4, IPv6, domain etc..)",
    url="https://github.com/conix-security/BTG",
    keywords = ['ioc'],
    license="GPL-3.0",
    classifiers=(
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
	'Topic :: Internet',
    ),
    data_files=[(os.path.expanduser("~/.config/BTG"), ["BTG/config/btg.cfg"])],
)
