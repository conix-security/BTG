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

import setuptools, sys, os, BTG

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'BTG'))
if not 'SUDO_USER' in os.environ:
    HOME_PATH = os.path.expanduser("~/.config/BTG")
else:
    USER = os.environ['SUDO_USER']
    HOME_PATH = "/home/%s/.config/BTG" % USER


with open("README.rst", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="BTG test",
    packages=setuptools.find_packages(),
    version="2.1.0",
    author="Conix Security",
    author_email="robin.marsollier@conix.fr",
    description="This tool allows you to qualify one or more potential malicious observables of various type (URL, MD5, SHA1, SHA256, SHA512, IPv4, IPv6, domain etc..)",
    long_description=long_description,
    include_package_data=True,
    url="https://github.com/conix-security/BTG",
    keywords = ['ioc'],
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
    data_files=[(HOME_PATH, ["BTG/config/btg.cfg"])],
    entry_points={
        'console_scripts':[
            'btg = BTG.BTG:main'
        ],
    },
)

os.chmod(HOME_PATH+"/btg.cfg", 0o666)
