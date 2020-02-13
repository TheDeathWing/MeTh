import os
import re 
import glob
import importlib
import meth as meth_path
import MeTh.modules.configs as meth_modules
import MeTH.modules as meth_src
import meth.modules as meth_config
from functools import wraps
from MeTH.core.exceptions import *
from core.colors import *

MODULES_DIR = meth_src.__path__[0]
"""
  Warning: This code snippet is from Threat9
  Credits: Routersploit
"""

def is_ipv4(address):
    """ Checks if given address is valid IPv4 address

    :param str address: IP address to check
    :return bool: True if address is valid IPv4 address, False otherwise
    """

    regexp = "^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    if re.match(regexp, address):
        return True

    return False


def is_ipv6(address):
    """ Checks if given address is valid IPv6 address

    :param str address: IP address to check
    :return bool: True if address is valid IPv6 address, False otherwise
    """

    regexp = "^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)%.*$"

    if re.match(regexp, address):
        return True

    return False


def convert_ip(address) :
    """ Converts IP to bytes

    :param str address: IP address that should be converted to bytes
    :return bytes: IP converted to bytes format
    """

    res = b""
    for i in address.split("."):
        res += bytes([int(i)])
    return res


def convert_port(port) :
    """ Converts Port to bytes

    :param int port: port that should be conveted to bytes
    :return bytes: port converted to bytes format
    """

    res = "%.4x" % int(port)
    return bytes.fromhex(res)


def index_modules(modules_directory = MODULES_DIR):
    """ Returns list of all exploits modules

    :param str modules_directory: path to modules directory
    :return list: list of found modules
    """
    modules = []
    for root, dirs, files in os.walk(modules_directory):
        _, package, root = root.rpartition("MeTH/modules/".replace("/", os.sep))
        root = root.replace(os.sep, ".")
        files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
        modules.extend(map(lambda x: ".".join((root, os.path.splitext(x)[0])), files))
    return modules


def restart_CLI():
   python = sys.executable
   os.execl(sys.executable, sys.executable, *sys.argv)
   curdir = os.getcwd()
def pythonize_path(path):
    """ Replaces argument to valid python dotted notation.

    ex. foo/bar/baz -> foo.bar.baz

    :param str path: path to pythonize
    :return str: pythonized path
    """

    return path.replace("/", ".")


def humanize_path(path):
    """ Replace python dotted path to directory-like one.

    ex. foo.bar.baz -> foo/bar/baz

    :param str path: path to humanize
    :return str: humanized path
    """

    return path.replace(".", "/")

def config_required(fn):
    """ Checks if module is loaded.

    Decorator that checks if any module is activated
    before executing command specific to modules (ex. 'run').
    """

    @wraps(fn)
    def wrapper(self, *args, **kwargs):
        if not self.current_config:
            print_error("You have to activate any configurstion with 'use' command.")
            return
        return fn(self, *args, **kwargs)

    try:
        name = "config_required"
        wrapper.__decorators__.append(name)
    except AttributeError:
        wrapper.__decorators__ = [name]
    return wrapper

def import_config(path):
    """ Imports exploit module
    
    :param str path: absolute path to exploit e.g. routersploit.modules.exploits.asus_auth_bypass
    :return: exploit module or error
    """
    try:
        module = importlib.import_module(path)
        if hasattr(module, "Payload"):
            return getattr(module, "Payload")
        elif hasattr(module, "Checker"):
            return getattr(module, "Checker")
        elif hasattr(module, "Exploit"):
            return getattr(module, "Exploit")
        else:
            raise ImportError("No module named '{}'".format(path))

    except (ImportError, AttributeError, KeyError) as err:
        raise MeTHException(
            "Error during loading '{}'\n\n"
            "Error: {}\n\n"
            "It should be valid path to the module. "
            "Use <tab> key multiple times for completion.".format(humanize_path(path), err)
        )

def print_error(msg="", *args, **kwargs):
   """
   Print error message [-]
   """
   print("[{RED}-{END}] %s".format(**colors)%(msg)) 
   
def print_status(msg="", *args, **kwargs):
   """
   Print status message  [*]
   """
   print("[{BLUE}*{END}] %s".format(**colors)%(msg))
def print_info(msg="", *args, **kwargs):
   """
   Print info message
   """
   print(msg)
def print_success(msg="", *args, **kwargs):
   """
   Print success mesage [+]
   """
   print("[{GREEN}+{END}] %s".format(**colors)%(msg))
   
def print_warning(msg="", *args, **kwargs):
   """
   Print warning message [~]
   """
   print("[{YELLOW}~{END}] %s".format(**colors)%(msg))
 
 
def print_table(headers, *args, **kwargs):
    """ Print table.

    example:

    Name            Current setting     Description
    ----            ---------------     -----------
    option_name     value               description
    foo             bar                 baz
    foo             bar                 baz

    :param headers: Headers names ex.('Name, 'Current setting', 'Description')
    :param args: table values, each element representing one line ex. ('option_name', 'value', 'description), ...
    :param kwargs: 'extra_fill' space between columns, 'header_separator' character to separate headers from content
    :return:
    """
    extra_fill = kwargs.get("extra_fill", 5)
    header_separator = kwargs.get("header_separator", "-")

    if not all(map(lambda x: len(x) == len(headers), args)):
        print_error("Headers and table rows tuples should be the same length.")
        return

    def custom_len(x):
        try:
            return len(x)
        except TypeError:
            return 0

    fill = []
    headers_line = '   '
    headers_separator_line = '   '
    for idx, header in enumerate(headers):
        column = [custom_len(arg[idx]) for arg in args]
        column.append(len(header))

        current_line_fill = max(column) + extra_fill
        fill.append(current_line_fill)
        headers_line = "".join((headers_line, "{header:<{fill}}".format(header=header, fill=current_line_fill)))
        headers_separator_line = "".join((
            headers_separator_line,
            "{:<{}}".format(header_separator * len(header), current_line_fill)
        ))

    print_info()
    print_info(headers_line)
    print_info(headers_separator_line)
    for arg in args:
        content_line = "   "
        for idx, element in enumerate(arg):
            content_line = "".join((
                content_line,
                "{:<{}}".format(element, fill[idx])
            ))
        print_info(content_line)

    print_info()
   
def pprint_dict_in_order(dictionary, order=None):
    """ Pretty dict print.

    Pretty printing dictionary in specific order. (as in 'show info' command)
    Keys not mentioned in *order* parameter will be printed in random order.

    ex. pprint_dict_in_order({'name': John, 'sex': 'male', "hobby": ["rugby", "golf"]}, ('sex', 'name'))

    Sex:
    male

    Name:
    John

    Hobby:
    - rugby
    - golf

    """
    order = order or ()

    def prettyprint(title, body):
        print_info("\n{}:".format(title.capitalize()))
        if not isinstance(body, str):
            for value_element in body:
                print_info("- ", value_element)
        else:
            print_info(body)

    keys = list(dictionary.keys())
    for element in order:
        try:
            key = keys.pop(keys.index(element))
            value = dictionary[key]
        except (KeyError, ValueError):
            pass
        else:
            prettyprint(element, value)

    for rest_keys in keys:
        prettyprint(rest_keys, dictionary[rest_keys])