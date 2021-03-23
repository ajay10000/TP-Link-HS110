#!/usr/bin/env python3
#
# TP-Link Wi-Fi Smart Plug Protocol Client
# For use with TP-Link HS-100 or HS-110
#
# by Lubomir Stroetmann
# Copyright 2016 softScheck GmbH
#
# Modified by Andrew P (ajay10000), 2018
# Python 3 version
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

import socket, argparse, json, urllib, urllib.request, logging, os, time, datetime, struct, configparser

# Get some variables outside this script
config = configparser.ConfigParser()

try:
    f = open("config.cfg", 'rb')
except OSError:
    print("Could not open/read file: config.cfg")
    sys.exit()

with f:
    config.read("config.cfg")
    domain = config['DETAILS']['DOMAIN']
    hs110_ip = config['DETAILS']['HS110_IP']

# Begin user editable variables
version = 3.5
logger_name = "hs110-1"  #used for log file names, messages, etc
debug_level="INFO"  # debug options DEBUG, INFO, WARNING, ERROR, CRITICAL
delay_time = 15 #update time in seconds
base_url = domain + "json.htm?type=command&param=udevice&nvalue=0"
monitor_list = ["voltage","current","power","usage"]
domoticz_idx = [90,91,108,93]
text_logging = True
track_state = True
hs110_switch_idx = 107
encoding = "utf-8"  # latin-1
datafile_columns = "Time,Voltage,Current,Power (W),Usage (kWHr)"
dailyfile_columns = "Date-Time,Usage (kWHr)"
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
        self.write_file(datafile,"w",datafile_columns + "\n")
      if not os.path.isfile(dailyfile):
        self.write_file(dailyfile,"w",dailyfile_columns + "\n")

    # Predefined Smart Plug Commands
    # For a full list of commands, consult tplink_commands.txt
    commands = {
        'info'     : '{"system":{"get_sysinfo":{}}}',
        'on'       : '{"system":{"set_relay_state":{"state":1}}}',
        'off'      : '{"system":{"set_relay_state":{"state":0}}}',
        'led_on'   : '{"system":{"set_led_off":{"off":0}}}',
        'led_off'  : '{"system":{"set_led_off":{"off":1}}}',
        'state'    : '{"system":{"get_sysinfo":{}}}',
        'cloudinfo': '{"cnCloud":{"get_info":{}}}',
        'wlanscan' : '{"netif":{"get_scaninfo":{"refresh":0}}}',
        'time'     : '{"time":{"get_time":{}}}',
        'schedule' : '{"schedule":{"get_rules":{}}}',
        'countdown': '{"count_down":{"get_rules":{}}}',
        'antitheft': '{"anti_theft":{"get_rules":{}}}',
        'reboot'   : '{"system":{"reboot":{"delay":1}}}',
        'reset'    : '{"system":{"reset":{"delay":1}}}',
        'energy'   : '{"emeter":{"get_realtime":{}}}'
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
    plainbytes = string.encode()
    logger.debug("Encoded string: {}".format(plainbytes))
    buffer = bytearray(struct.pack(">I", len(plainbytes)))
    for plainbyte in plainbytes:
      cipherbyte = key ^ plainbyte
      key = cipherbyte
      buffer.append(cipherbyte)
    return bytes(buffer)

  def decrypt(self, string):
    key = 171
    buffer = []
    for cipherbyte in string:
      plainbyte = key ^ cipherbyte
      key = cipherbyte
      buffer.append(plainbyte)
    plaintext = bytes(buffer)
    return plaintext.decode()

  # Generic file writing function
  def write_file(self,file_name,write_type,text):
    try:
      fil = open(file_name, write_type)
      fil.write(text)
    except IOError as e:
      logger.error("I/O error({}): {}".format(e.errno, e.strerror))
    else:
      fil.close()

  # Send json to app such as domoticz if requested in command (using "energy" or "state")
  def send_json(self,received_data):
    json_data = json.loads(received_data)
    logger.debug("json_data: {}".format(json_data))
    try:
      if self.read_state:
        # For getting the switch state only
        state = json_data['system']['get_sysinfo']['relay_state']
        full_url = domain + "json.htm?type=command&param=udevice&idx={}&nvalue={}".format(hs110_switch_idx,state)
        logger.debug("URL: {}".format(full_url))
        # Send the json string
        req = urllib.request.Request(full_url)
        with urllib.request.urlopen(req) as response:
          result = response.read()
        logger.debug("Logger response: {}".format(result))
      else:
        voltage = round(float(json_data['emeter']['get_realtime']['voltage_mv']) / 1000,2)
        current = round(float(json_data['emeter']['get_realtime']['current_ma']) / 1000,2)
        power = round(float(json_data['emeter']['get_realtime']['power_mw']) / 1000,2)
        usage = round(float(json_data['emeter']['get_realtime']['total_wh']) / 1000,3)

        for i in range(0,len(domoticz_idx)): # range is 0 based
          if i < len(domoticz_idx) - 1:
            logger.debug("IDX: {}, Item: {}, Value: {}".format(domoticz_idx[i],monitor_list[i],eval(monitor_list[i])))
            full_url = base_url + "&idx={}&svalue={}".format(domoticz_idx[i],eval(monitor_list[i]))
          else:
            # virtual sensor with sensor type Electric (Instant+Counter)
            logger.debug("IDX: {}, Items: {}, Values: {};{}".format(domoticz_idx[i],"Power (W), Usage (kWhr)",power,usage))
            full_url = base_url + "&idx={}&svalue={};{}".format(domoticz_idx[i],power,usage * 1000)
          logger.debug("URL: {}".format(full_url))
          # Send the json string
          req = urllib.request.Request(full_url, data=None)
          with urllib.request.urlopen(req) as response:
            result = response.read()
          logger.debug("Logger response: {}".format(result))

    except urllib.error.HTTPError as e:
      # Error checking to prevent crashing on bad requests
      logger.error("HTTP error({}): {}".format(e.errno, e.strerror))
    except urllib.error.URLError as e:
      logger.error("URL error({}): {}".format(e.errno, e.strerror))

    # write out the text file logs if required.  Don't log state.
    if text_logging and (not self.read_state):
      out = time.strftime("%Y-%m-%d %H:%M:%S") + "," + str(voltage) + "," + str(current) + "," + str(power) + "," + str(usage) + "\n"
      self.write_file(datafile, "a", out)

      if datetime.datetime.now() > self.next_daily_time:
        self.next_daily_time = datetime.datetime.combine(datetime.date.today() + datetime.timedelta(days=1),datetime.time(23,55,0))
        out = time.strftime("%Y-%m-%d %H:%M:%S") + "," + str(usage) + "\n"
        self.write_file(dailyfile, "a", out)

  # Send command to smart switch and receive reply
  # read_state is a special case for updating Domoticz with state
  def read_hs110(self, read_state = False):
    data = ""
    try:
      sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock_tcp.connect((self.ip, self.port))
      if read_state:
        self.read_state = True
        hs_cmd = '{"system":{"get_sysinfo":{}}}'
      else:
        self.read_state = False
        hs_cmd = self.cmd
      logger.debug("Command: {}".format(hs_cmd))
      logger.debug("Encrypted Command: {}".format(self.encrypt(hs_cmd)))
      sock_tcp.send(self.encrypt(hs_cmd))
      data = sock_tcp.recv(2048)
      sock_tcp.close()
      logger.debug("data: {}".format(data))
      received_data = self.decrypt(data[4:])
      # Successful read, reset error_count
      self.error_count = 0

    except socket.error:
      self.error_count += 1
      logger.error("Could not connect to host {}:{} {} times".format(self.ip,str(self.port),self.error_count))
      # Allow for a few connection errors.
      if self.error_count > 10:
        print("Could not connect to host " + self.ip + ":" + str(self.port) + " " + str(self.error_count) + " times") #debug
        raise SystemExit(0)
      else:
        return

    # json should be sent if command includes "energy" or "state"
    if "energy" in str(self.args) or "state" in str(self.args):
      logger.debug("Sent:     {}".format(hs_cmd))
      logger.debug("Received: {}".format(received_data))
      if received_data:  # OR (received_data is not None):
        self.send_json(received_data)
    else:
      # Direct command, so print to console and exit
      print("Sent:     ", hs_cmd)
      print("Received: ", received_data)
      # write out the text file logs if required
      if text_logging:
        out = time.strftime("%Y-%m-%d %H:%M:%S") + ",Command: " + hs_cmd + ",,\n"
        self.write_file(datafile, "a", out)
      raise SystemExit(0)

if __name__ == "__main__":
  hs = HS110()
  while True:
    hs.read_hs110()
    # check if state should be updated in domoticz
    if track_state:
      hs.read_hs110(track_state)
    time.sleep(delay_time)
