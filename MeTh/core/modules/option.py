import re
import os.path
import os
import threading
import time
from future.utils import with_metaclass, iteritems
from itertools import chain
from functools import wraps
from MeTh.utils import *
from MeTh.core.exceptions import OptionValidationError

GLOBAL_OPTS = {}
class Protocol:
    CUSTOM = "custom"
    TCP = "custom/tcp"
    UDP = "custom/udp"
    FTP = "ftp"
    FTPS = "ftps"
    SSH = "ssh"
    TELNET = "telnet"
    HTTP = "http"
    HTTPS = "https"
    SNMP = "snmp"



class Option(object):
    """ Exploit attribute that is set by the end user """

    def __init__(self, default, description="", advanced=False):
        self.label = None
        self.description = description

        try:
            self.advanced = bool(advanced)
        except ValueError:
            raise OptionValidationError("Invalid value. Cannot cast '{}' to boolean.".format(advanced))

        if default or default == 0:
            self.__set__("", default)
        else:
            self.display_value = ""
            self.value = ""

    def __get__(self, instance, owner):
        return self.value


class OptIP(Option):
    """ Option IP attribute """

    def __set__(self, instance, value):
        if not value or is_ipv4(value) or is_ipv6(value):
            self.value = self.display_value = value
        else:
            raise OptionValidationError("Invalid address. Provided address is not valid IPv4 or IPv6 address.")


class OptPort(Option):
    """ Option Port attribute """

    def __set__(self, instance, value):
        try:
            value = int(value)

            if 0 < value <= 65535:  # max port number is 65535
                self.display_value = str(value)
                self.value = value
            else:
                raise OptionValidationError("Invalid option. Port value should be between 0 and 65536.")
        except ValueError:
            raise OptionValidationError("Invalid option. Cannot cast '{}' to integer.".format(value))


class OptBool(Option):
    """ Option Bool attribute """

    def __init__(self, default, description="", advanced=False):
        self.description = description

        if default:
            self.display_value = "true"
        else:
            self.display_value = "false"

        self.value = default

        try:
            self.advanced = bool(advanced)
        except ValueError:
            raise OptionValidationError("Invalid value. Cannot cast '{}' to boolean.".format(advanced))

    def __set__(self, instance, value):
        if value == "true":
            self.value = True
            self.display_value = value
        elif value == "false":
            self.value = False
            self.display_value = value
        else:
            raise OptionValidationError("Invalid value. It should be true or false.")


class OptInteger(Option):
    """ Option Integer attribute """

    def __set__(self, instance, value):
        try:
            self.display_value = str(value)
            self.value = int(value)
        except ValueError:
            try:
                self.value = int(value, 16)
            except ValueError:
                raise OptionValidationError("Invalid option. Cannot cast '{}' to integer.".format(value))


class OptFloat(Option):
    """ Option Float attribute """

    def __set__(self, instance, value):
        try:
            self.display_value = str(value)
            self.value = float(value)
        except ValueError:
            raise OptionValidationError("Invalid option. Cannot cast '{}' to float.".format(value))


class OptString(Option):
    """ Option String attribute """

    def __set__(self, instance, value):
        try:
            self.value = self.display_value = str(value)
        except ValueError:
            raise OptionValidationError("Invalid option. Cannot cast '{}' to string.".format(value))


class OptMAC(Option):
    """ Option MAC attribute """

    def __set__(self, instance, value):
        regexp = r"^[a-f\d]{1,2}:[a-f\d]{1,2}:[a-f\d]{1,2}:[a-f\d]{1,2}:[a-f\d]{1,2}:[a-f\d]{1,2}$"
        if re.match(regexp, value.lower()):
            self.value = self.display_value = value
        else:
            raise OptionValidationError("Invalid option. '{}' is not a valid MAC address".format(value))


class OptWordlist(Option):
    """ Option Wordlist attribute """

    def __get__(self, instance, owner):
        if self.display_value.startswith("file://"):
            path = self.display_value.replace("file://", "")
            with open(path, "r") as f:
                lines = [line.strip() for line in f.readlines()]
                return lines

        return self.display_value.split(",")

    def __set__(self, instance, value):
        if value.startswith("file://"):
            path = value.replace("file://", "")
            if not os.path.exists(path):
                raise OptionValidationError("File '{}' does not exist.".format(path))

        self.value = self.display_value = value


class OptEncoder(Option):
    """ Option Encoder attribute """

    def __init__(self, default, description="", advanced=False):
        self.description = description

        if default:
            self.display_value = default
            self.value = default
        else:
            self.display_value = ""
            self.value = None

        try:
            self.advanced = bool(advanced)
        except ValueError:
            raise OptionValidationError("Invalid value. Cannot cast '{}' to boolean.".format(advanced))

    def __set__(self, instance, value):
        encoder = instance.get_encoder(value)

        if encoder:
            self.value = encoder
            self.display_value = value
        else:
            raise OptionValidationError("Encoder not available. Check available encoders with `show encoders`.")
            
class ExploitOptionsAggregator(type):
    """ Metaclass for exploit base class.

    Metaclass is aggregating all possible Attributes that user can set
    for tab completion purposes.
    """

    def __new__(cls, name, bases, attrs):
        try:
            base_exploit_attributes = chain([base.exploit_attributes for base in bases])
        except AttributeError:
            attrs["exploit_attributes"] = {}
        else:
            attrs["exploit_attributes"] = {k: v for d in base_exploit_attributes for k, v in iteritems(d)}

        for key, value in iteritems(attrs.copy()):
            if isinstance(value, Option):
                value.label = key
                attrs["exploit_attributes"].update({key: [value.display_value, value.description, value.advanced]})
            #elif key == "__info__":
            #     attrs["_{}{}".format(name, key)] = value
            #    del attrs[key]
            elif key in attrs["exploit_attributes"]:  # removing exploit_attribtue that was overwritten
                del attrs["exploit_attributes"][key]  # in the child and is not an Option() instance

        return super(ExploitOptionsAggregator, cls).__new__(cls, name, bases, attrs)


class BaseExploit(with_metaclass(ExploitOptionsAggregator, object)):
    @property
    def options(self):
        """ Returns list of options that user can set.

        Returns list of options aggregated by
        ExploitionOptionsAggegator metaclass that user can set.

        :return: list of options that user can set
        """

        return list(self.exploit_attributes.keys())

    def __str__(self):
        return self.__module__.split('.', 2).pop().replace('.', os.sep)


class Checker(BaseExploit):
    """ Base class for exploits """

    target_protocol = Protocol.CUSTOM

    def run(self):
        raise NotImplementedError("You have to define your own 'run' method.")

    def check(self):
        raise NotImplementedError("You have to define your own 'check' method.")

    def run_threads(self, threads_number, target_function, *args, **kwargs):
        """ Run function across specified number of threads

        :param int thread_number: number of threads that should be executed
        :param func target_function: function that should be executed accross specified number of threads
        :param any args: args passed to target_function
        :param any kwargs: kwargs passed to target function
        :return None
        """

        threads = []
        threads_running = threading.Event()
        threads_running.set()

        for thread_id in range(int(threads_number)):
            thread = threading.Thread(
                target=target_function,
                args=chain((threads_running,), args),
                kwargs=kwargs,
                name="thread-{}".format(thread_id),
            )
            threads.append(thread)

            # print_status("{} thread is starting...".format(thread.name))
            thread.start()

        start = time.time()
        try:
            while thread.isAlive():
                thread.join(1)

        except KeyboardInterrupt:
            threads_running.clear()

        for thread in threads:
            thread.join()
            # print_status("{} thread is terminated.".format(thread.name))

        print_status("Elapsed time: {0:.4f} seconds".format(round(time.time() - start, 2)))


def multi(fn):
    """ Decorator for exploit.Exploit class

    Decorator that allows to feed exploit using text file containing
    multiple targets definition. Decorated function will be executed
    as many times as there is targets in the feed file.

    WARNING:
    Important thing to remember is fact that decorator will
    supress values returned by decorated function. Since method that
    perform attack is not supposed to return anything this is not a problem.

    """

    @wraps(fn)
    def wrapper(self, *args, **kwargs):
        if self.target.startswith("file://"):
            original_target = self.target
            original_port = self.port

            _, _, feed_path = self.target.partition("file://")
            try:
                with open(feed_path) as file_handler:
                    for target in file_handler:
                        target = target.strip()
                        if not target:
                            continue

                        self.target, _, port = target.partition(":")
                        if port:
                            self.port = port
                        else:
                            self.port = original_port

                        fn(self, *args, **kwargs)
                    self.target = original_target
                    self.port = original_port
                    return  # Nothing to return, ran multiple times

            except IOError:
                return
        else:
            return fn(self, *args, **kwargs)

    return wrapper


class DummyFile(object):
    """ Mocking file object. Optimilization for the "mute" decorator. """
    def write(self, x):
        pass


def mute(fn):
    """ Suppress function from printing to sys.stdout """

    @wraps(fn)
    def wrapper(self, *args, **kwargs):
        thread_output_stream.setdefault(threading.current_thread(), []).append(DummyFile())
        try:
            return fn(self, *args, **kwargs)
        finally:
            thread_output_stream[threading.current_thread()].pop()
    return wrapper


class LockedIterator(object):
    def __init__(self, it):
        self.lock = threading.Lock()
        self.it = it.__iter__()

    def __iter__(self):
        return self

    def next(self):
        self.lock.acquire()
        try:
            item = next(self.it)

            if type(item) is tuple:
                return (item[0].strip(), item[1].strip())
            elif type(item) is str:
                return item.strip()

            return item
        finally:
            self.lock.release()