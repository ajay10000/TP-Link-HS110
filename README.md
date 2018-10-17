# TP-Link-HS110
TP-Link Wi-Fi Smart Plug Protocol Client (Python 2.7 and Python3)

This is a fork of Softscheck's brilliant job of reverse engineering the TP-Link HS100/110 smart switches: https://www.softscheck.com/en/reverse-engineering-tp-link-hs110/.  

This version will send the energy information from a HS110 to Domoticz at set intervals.  i.e. you don't need CRON to do this.  

You can also send direct commands to the HS110 (documented in the code).  All results can be logged to a text file.

Example logs from command line: python tplink_hs110.py -c energy
Sent:      {"emeter":{"get_realtime":{}}}
Received:  {"emeter":{"get_realtime":{"voltage_mv":242630,"current_ma":19,"power_mw":1223,"total_wh":184,"err_code":0}}}

If 'energy' is used in the command line as above, the data is sent to Domoticz using JSON.
If any other command is used, the switch will respond directly and show the result following the command.

This version also supports text logging.

v0.5 2018/08/11 Supports sending the relay (switch) status to Domoticz.

v3.5 2018/09/15 Python3 parallel version, with thanks to https://github.com/GadgetReactor/pyHS100/blob/master/pyHS100/protocol.py for showing how to convert the encrypt/decrypt definitions.

NOTE: If you are getting a KeyError: 'voltage_mv', then your HS110 may be returning volts, amps and watts rather than millivolts, milliamps and milliwatts.  You will see it in the logs, something like this:
2018-10-02 17:49:29,433:__main__:DEBUG:json_data: {'emeter': {'get_realtime': {'voltage': [b]230.421503[/b], 'power': 49.65685, 'current': 0.414566, 'total': 2.304, 'err_code': 0}}}  Have a look at this post https://www.domoticz.com/forum/viewtopic.php?p=194420&sid=add7294afd026954ab0edac00a372730#p193180 for values to change.

Another note: I'm not a Python programmer, so if you find anything that isn't OK, please let me know.  Thanks!
