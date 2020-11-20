#!/usr/bin/env python

import yaml
import logging

from os import path
from logging.config import dictConfig as _dictConfig

__author__ = "Samuel Marks"
__version__ = "0.0.7-gamma"


def get_logger(name=None):
    with open(path.join(path.dirname(__file__), "_data", "logging.yml"), "rt") as f:
        data = yaml.load(f, Loader=yaml.SafeLoader)
    logging.config.dictConfig(data)
    return logging.getLogger(name=name)


root_logger = get_logger()
