# -*- coding: utf-8 -*-


import logging
import logging.config
from os import path

import yaml

__author__ = "Samuel Marks"
__version__ = "0.0.8"
__description__ = "Certbot deployment module for Fabric (offregister)"


def get_logger(name=None):
    """
    Create logger—with optional name—with the logging.yml config

    :param name: Optional name of logger
    :type name: ```Optional[str]```

    :return: instanceof Logger
    :rtype: ```Logger```
    """
    with open(path.join(path.dirname(__file__), "_data", "logging.yml"), "rt") as f:
        data = yaml.load(f, Loader=yaml.SafeLoader)
    logging.config.dictConfig(data)
    return logging.getLogger(name=name)


root_logger = get_logger()

__all__ = ["get_logger", "root_logger"]
