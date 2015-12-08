#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name     = 'thorin',
    packages = ['thorin'],
    version  = '1.0.10',
    requires = ['python (>= 3.0)'],
    install_requires = [
        'lesscpy',
        'Jinja2',
    ],
    description  = 'Thorin - Web Framework',
    author       = 'Phil Situmorang',
    author_email = 'philmsk@gmail.com',
    url          = 'https://github.com/philsitumorang/thorin',
    download_url = 'https://github.com/philsitumorang/thorin/archive/master.zip',
    license      = 'MIT License',
    keywords     = 'thorin',
    classifiers  = [
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
    ],
    package_data={'thorin': ['thorin_tests/*.*']}
)
