#!/usr/bin/env python

import logging
from os import path

import yaml

__author__ = "Samuel Marks"
__version__ = "0.0.7-gamma"


def get_logger(name=None):
    with open(path.join(path.dirname(__file__), "_data", "logging.yml"), "rt") as f:
        data = yaml.load(f, Loader=yaml.SafeLoader)
    logging.config.dictConfig(data)
    return logging.getLogger(name=name)


root_logger = get_logger()
