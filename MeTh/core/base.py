#!/bin/usr/env python2 
#! -*- coding: UTF-8 -*-
import sys
import os
import random
import shutil
from Queue import Queue
from MeTH.core.exceptions import *
from MeTH.utils import *
PATH_DIR = meth_path.__path__[0]
CONFIG_DIR = meth_modules.__path__[0]
SRC_DIR = meth_src.__path__[0]
printer_queue = Queue()

class MeTh(object):
 def __init__(self):
   global attributes
   self._name = "MeTH"
   self._prompt_template = "{}{} > "
   self._base_prompt = self._prompt_template.format('', self._name)
   self.current_config = None
   self.module_prompt_template = "{} (\033[1;31m{}\033[0m) > " 
   self.filextension = ".mt"
   self.modules = index_modules()
   self.configdir = humanize_path(CONFIG_DIR)
   #Declaring the info messages
   self.__messages_info()
   
 @property
 def _get_config_metadata(self):
    return getattr(self.current_config,"__info__")
    
 def _prompt_helper(self):
    if self.current_config:
      try:
         return self.module_prompt_template.format(self._name, self._get_config_metadata["Name"])
      except (AttributeError, KeyError):
         return self.module_prompt_template.format(self._name, "UnnamedModule")
    else:
      return self._base_prompt
      
   
 def _getproxys(self):
  """
   Function return a proxy
   in case proxys in attributes is defined
   it will return a random proxy
   
   : return proxies
  """
  if self.attributes["proxies"] is not "":
    try: 
       with open(self.attributes["proxies"]) as proxylist:
          lines = proxylist.readlines()
          proxies = random.choice(lines)
       return proxies
    except IOError:
      print_error("Unknown error!")
  else:
    res = reqs.get('https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt', headers={'User-Agent':'Mozilla/5.0'})
    lines = res.text.split("\n")
    proxies = random.choice(lines)
    return proxies
    
 def get_command_handler(self, command):
   try:
      command_handler = getattr(self, "command_{}".format(command))
   except AttributeError:
      raise MeTHException("Unknown command: '{}'".format(command))
   return command_handler
   
 def parse_line(self, line):
  """ Split line into command and argument.
 
   :param line: line to parse
   :return: (command, argument, named_arguments)
   RouterSploit credits :3
  """
  kwargs = dict()
  command, _, arg = line.strip().partition(" ")
  args = arg.strip().split()
  for word in args:
    if '=' in word:
       (key, value) = word.split('=', 1)
       kwargs[key.lower()] = value
       arg = arg.replace(word, '')
  return command, ' '.join(arg.split()), kwargs
  
 def __messages_info(self):
  self.banner = """\033[1;36m
        ███╗   ███╗███████╗████████╗██╗  ██╗
        ████╗ ████║██╔════╝╚══██╔══╝██║  ██║
        ██╔████╔██║█████╗     ██║   ███████║
        ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║
        ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║
        ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝""
  \033[1;32mMulti Account Credentials Checker 1.0 \033[1;31mBy: \033[1;33mMrZ3r0\033[0m
  """
  self.global_help = """
    Core commands
    ==============\n 
    Command               Description
    --------              ------------
    help                     display this help menu
    use <module>             load a module or checker
    back                     back the current menu
    exit                     close the console
    info                     show info about developer and framework
    exec <command> <args>    execute a command from shell
    run                      run a given module using command "use"
    show info|options|all    show information, modules and options      
    unset <value>            unset global value was set(No working)
    load plugin|framework    (Will be added in news update :] )
    set  <value>             set value from current module
  """
  self.info_menu = """\033[0m
  MeTH(Multi Account Credentials Checker) is the first multi checker
  of accounts open-source and executable bassed in python2.
  Dedicated to account intrusion for pentesting.\n
  [Disclaimer] 
  Our framework was developed for controlled envoriments, the
  misuse that is done with it is not our responsibility.
  Code snippets from \033[1;31mRoutersploit\033[0m.
  --> Only for pentesting <--\n
  [Developer] 
  Mr-Z3r0, creator and developer of The framework.
  I love hacking and programming, hacking you since 2018-2020
  Creator and admin of TheDeathWing.\n	
  [Sponsors]
  Not sponsors. Want u be one?
  """
  
 @config_required
 def command_back(self, *args, **kwargs):
   self.current_config = None
   
 def start(self):
  os.system("clear")
  print(self.banner)
  printer_queue.join()
  while True:
    try:
      command, args, kwargs = self.parse_line(raw_input(self._prompt_helper()))
      if not command:
        continue
      command_handler = self.get_command_handler(command)
      command_handler(args, **kwargs)
    except MeTHException as Err:
     #print("\033[1;31m%s\033[0m"%(Err))
     self._help_menu(command)
    except (EOFError, KeyboardInterrupt, SystemExit):
      #print_info()
      print_error("Ups, METH was stopped")
      break
    finally:
      printer_queue.join()
      
 def _check_file(self, fname):
    try:
       f = open(fname)
    except IOError:
       print_error("File `{}` can't be opened".format(fname))
       return False
       
 @config_required
 def command_set(self, *args, **kwargs):
    key, _, value = args[0].partition(" ")
    if key in self.current_config.options and value is not "":
      #setattr(self.attributes, key, value)
      if self._check_file(value) != False:
        setattr(self.current_config, key, value)
        self.current_config.exploit_attributes[key][0] = value
        if kwargs.get("glob", False):
          GLOBAL_OPTS[key] = value
        print_success("{} => {}".format(key, value))
    else:
     print_error("You can't set option '{}'.\n"
    "Available options: {}".format(key, self.current_config.options))
 @config_required
 def _show_info(self, *args, **kwargs):
    pprint_dict_in_order(
     self._get_config_metadata,
      ("Name", "Description", "Authors", "LastModified"),
    )
    print_info()
 @config_required
 def get_opts(self, *args):
    """ Generator returning module's Option attributes (option_name, option_value, option_description)
 
    :param args: Option names
    :return:
    """
    for opt_key in args:
       try:
           opt_description = self.current_config.exploit_attributes[opt_key][1]
           opt_display_value = self.current_config.exploit_attributes[opt_key][0]
           if self.current_config.exploit_attributes[opt_key][2]:
               continue
       except (KeyError, IndexError, AttributeError):
           pass
       else:
           yield opt_key, opt_display_value, opt_description
 
 @config_required
 def get_opts_adv(self, *args):
    """ Generator returning module's advanced Option attributes (option_name, option_value, option_description)
 
    :param args: Option names
    :return:
    """
    for opt_key in args:
       try:
          opt_description = self.current_config.exploit_attributes[opt_key][1]
          opt_display_value = self.current_config.exploit_attributes[opt_key][0]
       except (KeyError, AttributeError):
          pass
       else:
          yield opt_key, opt_display_value, opt_description
 @config_required
 def _show_options(self, *args, **kwargs):
     target_names = ["target", "port", "ssl", "rhost", "rport", "lhost", "lport"]
     target_opts = [opt for opt in self.current_config.options if opt in target_names]
     module_opts = [opt for opt in self.current_config.options if opt not in target_opts]
     headers = ("Name", "Current settings", "Description")
     
     #print_info("\nTarget options:")
     #print_table(headers, *self.get_opts(*target_opts))
 
     if module_opts:
        print_info("\nModule options:")
        print_table(headers, *self.get_opts(*module_opts))
    
     print_info()
 def __show_options(self, root=''):
     for module in [module for module in self.modules if module.startswith(root)]:
        print_info(module.replace('.', os.sep))
        
 def _show_all(self, *args, **kwargs):
     self.__show_options()
     
 def _show_configs(self, *args, **kwargs):
     self.__show_options('configs')
     
 def command_show(self, *args, **kwargs):
     sub_command = args[0]
     try:
        getattr(self, "_show_{}".format(sub_command))(*args, **kwargs)
     except AttributeError:
        print_error("show subcommand doesn't exists")
        
 def command_info(self, *args, **kwargs):
    print(self.info_menu)
    
 def _help_menu(self, option):
   msg = [
       'What? i didnt understand. Try help.',
       'That command dont appears to exists.',
       'Sorry but i dont know this command.',
       'Maybe you need help, try command \'help\'.'
   ]
   print("\033[1;31m%s\033[0m"%(random.choice(msg)))
   return
   
 def command_exec(self, *args, **kwargs):
    os.system(args[0])
    
 def copy_file(self, fname, *args, **kwargs):
   #print os.path.isfile(fname)
   filen = os.path.basename(fname)
   try:
      print_status("Copying file...")
      shutil.copyfile(fname, self.configdir+filen)
      print_success("The file {fname} was copied successful.".format(fname=fname))
   except shutil.Error as e:
      print_error("Unable to copy file. %s" % e)
      
 def check_extension(self, file, *args, **kwargs):
    file = PATH_DIR+"/"+file
    if file.endswith(self.filextension):
      try:
        f = open(file)
        return True
      except IOError:
        print_error("File not accessible")
    else:
      print_error("File extension is not allowed.")
        
 @config_required
 def command_run(self, *args, **kwargs):
   print_status("Running module...")
   try:
      self.current_config.run()
   except KeyboardInterrupt:
      print_error("Accion cancelled by user")
   #except:
   #    print_error("An error ocurred")
   
 def command_help(self, *args, **kwargs):
    print_info(self.global_help)
    
 def command_use(self, config_file):
   config_file = pythonize_path(config_file)
   config_file = ".".join(("MeTH", "modules", config_file))
   try:
      self.current_config = import_config(config_file)()
   except MeTHException as err:
      print_error(str(err))
 def command_exit(self, *args, **kwargs):
   raise EOFError
   