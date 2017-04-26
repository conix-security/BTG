from multiprocessing import Manager
import ast
from ConfigParser import ConfigParser

class Config():

    __args=None

    @staticmethod
    def get_instance():
        if not Config.__args:
            Config.__args = Manager().dict()
            Config._parse_config()
            return Config.__args
        else:
            return Config.__args

    @staticmethod
    def _parse_config():
        conf = ConfigParser()
        conf.read("config.ini")
        Config.__args = {option : ast.literal_eval(conf.get(section,option)) for section in conf.sections() for option in conf.options(section)}


