#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys
import os
from glob import glob
import platform
from setuptools import setup
from cloudmon import __version__

with open('README.md') as readme_file:
    readme = readme_file.read()

with open('CHANGELOG.md') as history_file:
    history = history_file.read()

requirements = [
    'setuptools==3.6',
    'cs==1.0.0',
    'configobj==5.0.6',
    'Cerberus==1.1',
    'Unidecode==0.04.18',
    'pika==0.10.0',
    'python_daemon==2.1.2',
    'pyzmq==16.0.2',
    'pyzabbix==0.7.4',
    'redis==2.10.6',
    'boto3==1.7.80',
    # 'setproctitle',
]

test_requirements = [
    # TODO: put package test requirements here
]

# get virtualenv
if hasattr(sys, 'real_prefix'):
    virtualenv = sys.prefix
else:
    virtualenv = False

distro = platform.dist()[0]
distro_major_version = platform.dist()[1].split('.')[0]
if not distro:
    if 'amzn' in platform.uname()[2]:
        distro = 'centos'

if virtualenv:
    etc = os.path.join(virtualenv, 'etc/cloudmon')
    initd = os.path.join(virtualenv, 'etc/init.d')
else:
    etc = '/etc/cloudmon'
    initd = '/etc/init.d'


data_files = [
    ('share/cloudmon', ['LICENSE']),
    (etc, glob('conf/*.conf')),
    (initd, ['bin/init.d/cloudmon'])
]

setup(
    name='cloudmon',
    version=__version__,
    description="Monitoring Orchestrator for Clouds",
    long_description=readme + '\n\n' + history,
    author="Adolfo Suzzano",
    author_email='adolfo@ngxlabs.com',
    url='https://github.com/globocom/cloudmon',
    packages=[
        'cloudmon',
        'cloudmon.connector',
        'cloudmon.utils'
    ],
    scripts=['bin/cloudmon'],
    package_dir={'cloudmon':
                 'cloudmon'},
    include_package_data=True,
    python_requires='>=2.7, !=3.*',
    install_requires=requirements,
    data_files=data_files,
    license="MIT license",
    zip_safe=False,
    keywords='cloudmon',
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    test_suite='tests',
    tests_require=test_requirements
)
