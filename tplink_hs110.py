#!/usr/bin/env python2
#
# TP-Link Wi-Fi Smart Plug Protocol Client
# For use with TP-Link HS-100 or HS-110
#
# by Lubomir Stroetmann
# Copyright 2016 softScheck GmbH
#
# Modified by Andrew P, 2018
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Example from command line:
# python tplink_hs110.py -c energy
# Sent:      {"emeter":{"get_realtime":{}}}
# Received:  {"emeter":{"get_realtime":{"voltage_mv":242630,"current_ma":19,"power_mw":1223,"total_wh":184,"err_code":0}}}

import socket, argparse, json, urllib, urllib2, logging, os, time, datetime
from struct import pack

# Begin user editable variables
version = 0.4
logger_name = "hs110-1"  #used for log file names, messages, etc
debug_level='INFO'  # debug options DEBUG, INFO, WARNING, ERROR, CRITICAL
delay_time = 15             # Update time in seconds
domain="http://rpi3:8080"   # Use your Domoticz IP or hostname and port
base_url = domain + "/json.htm?type=command&param=udevice&nvalue=0"
monitor_list = ["voltage","current","kwhr"]
domoticz_idx = [90,91,93]   # Use your Domoticz indexes after setting up the hardware and devices
hs110_ip = "192.168.25.60"  # Replace this with your HS110 IP
text_logging = True         # Log to text file as well as to Domoticz, in same directory as this file
datafile_columns = "Time,Voltage,Current,Power"
dailyfile_columns = "Date-Time,kWHr"
# End user editable variables

log_path = os.path.dirname(os.path.realpath(__file__)) 
log_level = getattr(logging, debug_level.upper(), 10)
logging.basicConfig(filename=log_path + "/" + logger_name + ".log", level=log_level, format="%(asctime)s:%(name)s:%(levelname)s:%(message)s")
logger = logging.getLogger(__name__)
dailyfile = log_path + "/" + logger_name + "_daily.csv"
datafile = log_path + "/" + logger_name + "_data.csv"
logger.info("{} version {} has started...".format(logger_name, version))

class HS110:
  def __init__(self):
    self.error_count = 0
    if text_logging:
      self.next_daily_time = datetime.datetime.combine(datetime.date.today(),datetime.time(23,55,0))
      # Set up headers for log and daily files
      if not os.path.isfile(datafile):
        self.write_file(datafile,'w',datafile_columns + "\n")
      if not os.path.isfile(dailyfile):
        self.write_file(dailyfile,'w',dailyfile_columns + "\n")
      
    # Predefined Smart Plug Commands
    # For a full list of commands, consult tplink_commands.txt
    commands = {
          'info'     : '{"system":{"get_sysinfo":{}}}',
          'on'       : '{"system":{"set_relay_state":{"state":1}}}',
          'off'      : '{"system":{"set_relay_state":{"state":0}}}',
          'cloudinfo': '{"cnCloud":{"get_info":{}}}',
          'wlanscan' : '{"netif":{"get_scaninfo":{"refresh":0}}}',
          'time'     : '{"time":{"get_time":{}}}',
          'schedule' : '{"schedule":{"get_rules":{}}}',
          'countdown': '{"count_down":{"get_rules":{}}}',
          'antitheft': '{"anti_theft":{"get_rules":{}}}',
          'reboot'   : '{"system":{"reboot":{"delay":1}}}',
          'reset'    : '{"system":{"reset":{"delay":1}}}',
          'energy'   : '{"emeter":{"get_realtime":{}}}',
    }
    
    # Parse commandline arguments
    parser = argparse.ArgumentParser(description="TP-Link Wi-Fi Smart Plug Client v" + str(version))
    parser.add_argument("-t", "--target", metavar="<hostname>", help="Target hostname or IP address", type=self.validHostname)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--command", metavar="<command>", help="Preset command to send. Choices are: "+", ".join(commands), choices=commands)
    group.add_argument("-j", "--json", metavar="<JSON string>", help="Full JSON string of command to send")
    self.args = parser.parse_args()

    # Set target IP, port and command to send
    self.port = 9999
    if self.args.target is None:
      self.ip = hs110_ip
    else:
      self.ip = self.args.target
    if self.args.command is None:
      self.cmd = self.args.json
    else:
      self.cmd = commands[self.args.command]
    
  # Check for valid hostname
  def validHostname(self, hostname):
    try:
      socket.gethostbyname(hostname)
    except socket.error:
      parser.error("Invalid hostname.")
    return hostname

  # Encryption and Decryption of TP-Link Smart Home Protocol
  # XOR Autokey Cipher with starting key = 171
  def encrypt(self, string):
    key = 171
    result = pack('>I', len(string))
    for i in string:
      a = key ^ ord(i)
      key = a
      result += chr(a)
    return result

  def decrypt(self, string):
    key = 171
    result = ""
    for i in string:
      a = key ^ ord(i)
      key = ord(i)
      result += chr(a)
    return result

  # Generic file writing function
  def write_file(self,file_name,write_type,text):
    try:
      fil = open(file_name, write_type)
      fil.write(text)
    except IOError as e:
      logger.error("I/O error({}): {}".format(e.errno, e.strerror))
    else:
      fil.close()

  # Send json to app such as domoticz if requested in command (using 'energy')
  def send_json(self,received_data):
    json_data = json.loads(received_data)
    voltage = float(json_data['emeter']['get_realtime']['voltage_mv']) / 1000
    current = float(json_data['emeter']['get_realtime']['current_ma']) / 1000
    power = float(json_data['emeter']['get_realtime']['power_mw']) / 1000
    kwhr = float(json_data['emeter']['get_realtime']['total_wh'])
      
    try:
      for i in range(0,len(domoticz_idx)): # range is 0 based
        if i < len(domoticz_idx) - 1:
          logger.debug("IDX: {}, Value: {}".format(domoticz_idx[i],monitor_list[i]))
          full_url = base_url + "&idx={}&svalue={:.2f}".format(domoticz_idx[i],eval(monitor_list[i]))
        else:
          # virtual sensor with sensor type 'Electric (Instant+Counter)
          logger.debug("IDX: {}, Values: {};{}".format(domoticz_idx[i],power,kwhr))
          full_url = base_url + "&idx={}&svalue={:.2f};{:.2f}".format(domoticz_idx[i],power,kwhr)
        logger.debug("URL: {}".format(full_url))
        # Send the json string
        urllib2.urlopen(full_url)
        
    except urllib2.HTTPError as e:
      # Error checking to prevent crashing on bad requests
      logger.error("HTTP error({}): {}".format(e.errno, e.strerror))
    except urllib2.URLError as e:
      logger.error("URL error({}): {}".format(e.errno, e.strerror))
    
    # write out the text file logs if required  
    if text_logging:      
      out = time.strftime("%Y-%m-%d %H:%M") + "," + str(voltage) + "," + str(current) + "," + str(power) + "\n"
      self.write_file(datafile, 'a', out)
      
      if datetime.datetime.now() > self.next_daily_time:
        self.next_daily_time = datetime.datetime.combine(datetime.date.today() + datetime.timedelta(days=1),datetime.time(23,55,0))
        out = time.strftime("%Y-%m-%d %H:%M") + "," + str(kwhr) + "\n"
        self.write_file(dailyfile, 'a', out)

  # Send command to smart switch and receive reply        
  def read_hs110(self):
    data = ""
    try:
      sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock_tcp.connect((self.ip, self.port))
      sock_tcp.send(self.encrypt(self.cmd))
      data = sock_tcp.recv(2048)
      sock_tcp.close()
      received_data = self.decrypt(data[4:])
      # Successful read, reset error_count
      self.error_count = 0

    except socket.error:
      self.error_count += 1
      logger.error("Could not connect to host {}:{} {} times".format(self.ip,str(self.port),self.error_count))
      # Allow for a few connection errors.
      if self.error_count > 10:
        print "Could not connect to host " + self.ip + ":" + str(self.port) + " " + str(self.error_count) + " times"  #debug
        raise SystemExit(0)
      else:
        return
      
    # json should be sent if command includes 'energy'
    if "energy" in str(self.args):
      logger.debug("Sent:     {}".format(self.cmd))
      logger.debug("Received: {}".format(received_data))
      if received_data is not None:
        self.send_json(received_data)
    else:
      # Direct command, so print to console and exit
      print "Sent:     ", self.cmd
      print "Received: ", received_data
      # write out the text file logs if required  
      if text_logging:      
        out = time.strftime("%Y-%m-%d %H:%M") + ",Command: " + self.cmd + ",,\n"
        self.write_file(datafile, 'a', out)
      raise SystemExit(0)

if __name__ == '__main__':
  hs = HS110()
  while True:
    hs.read_hs110()
    time.sleep(delay_time)
