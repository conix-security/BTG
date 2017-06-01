import ast
import os
from ConfigParser import ConfigParser
from multiprocessing import Manager


class Config():

    __args = None

    @staticmethod
    def get_instance():
        if not Config.__args:
            Config.__args = Manager().dict()
            Config._parse_config()
            return Config.__args
        return Config.__args

    @staticmethod
    def _parse_config():
        conf = ConfigParser()
        dir_path = os.path.dirname(os.path.realpath(__file__))
        conf.read("%s/config.ini"%dir_path)
        Config.__args = {option: ast.literal_eval(conf.get(section, option)) for section in conf.sections() for option in conf.options(section)}
