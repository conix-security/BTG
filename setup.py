#!/usr/bin/env python3
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

import os
import setuptools
import sys

import BTG
_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_PATH, 'BTG'))

if 'SUDO_USER' in os.environ:
    USER = os.environ['SUDO_USER']
    CONFIG_PATH = "/home/%s/.config/BTG" % USER
else:
    CONFIG_PATH = os.path.expanduser("~/.config/BTG")

with open("README.rst", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="BTG",
    packages=setuptools.find_packages(),
    version="2.2",
    author="Conix Security",
    author_email="robin.marsollier@conix.fr",
    description="This tool allows you to qualify one or more potential malicious observables of various type (URL, MD5, SHA1, SHA256, SHA512, IPv4, IPv6, domain etc..)",
    long_description=long_description,
    url="https://github.com/conix-security/BTG",
    keywords=["ioc"],
    license="GPLv3",
    classifiers=(
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
    ),
    package_data={'BTG': ["data/modules_descriptor.csv"]},
    include_package_data=True,
    data_files=[(CONFIG_PATH, ["BTG/config/btg.cfg"])],
    entry_points={
        'console_scripts': [
            'btg = BTG.BTG:main'
        ],
    },
)

os.chmod(CONFIG_PATH+"/btg.cfg", 0o666)
os.chmod(_PATH+"/BTG/data/modules_descriptor.csv", 0o666)
