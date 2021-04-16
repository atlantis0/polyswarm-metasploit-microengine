#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

setup(
    name='addis_ababa',
    version='0.1.0',
    description='addisengine',
    author='Sirack',
    author_email='sirackh@gmail.com',
    install_requires=[
        'polyswarm-artifact',
        'polyswarm-client'
    ],
    include_package_data=True,
    packages=find_packages(),
    package_dir={
        'addis_ababa': 'addis_ababa',
    },
)
