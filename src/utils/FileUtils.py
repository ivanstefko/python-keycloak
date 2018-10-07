import json
import ConfigParser


class FileUtils(object):

    @staticmethod
    def open_json_file(filename):
        """
        Static method used for loading data from external file.

        :filename: the path with filename to be loaded
        :return: loaded file in json form
        """
        with open(filename, 'r') as f:
            return json.load(f)

    @staticmethod
    def open_ini_file(filename):
        """
        Static method used for loading data from external ini file.

        :filename: the path with filename to be loaded
        :return: loaded file in ini form
        """
        config = ConfigParser.ConfigParser()
        config.read(filename)
        return config
