#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2014-2017 Mozilla Corporation
# Author: gdestuynder@mozilla.com

import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
        name = "bcorp",
        py_modules = [],
        version = "0.5",
        author = "Guillaume Destuynder",
        author_email = "gdestuynder@mozilla.com",
        description = ("A BeyondCorp style CLI client for the Federated Access Proxy"),
        license = "MPL",
        keywords = "ssh sts bcorp beyond corp federated access proxy sso iam",
        url = "https://github.com/mozilla-iam/bcorp",
        long_description = read('README.md'),
        install_requires = ['requests', 'pyaml'],
        classifiers = [
            "Development Status :: 5 - Production/Stable",
            "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
            ],
        scripts = ['bcorp'],
        data_files = [('', ['bcorp.yml'])],
)
