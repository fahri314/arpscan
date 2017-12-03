__author__ = 'Fahri Güreşçi'
__version__ = '1.0'

# arpscan is a network security program.
# Copyright (C) (2017)

# arpscan is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

# WARNING
# This was written for educational purpose and pentest only. Use it at your own risk.
# Please remember... your action will be logged in target system...
# Author will not be responsible for any damage !!
# Use it with your own risk

import sys
from scapy.all import *
from datetime import datetime
start_time = datetime.now()

if sys.platform == 'linux-i386' or sys.platform == 'linux2' or sys.platform == 'darwin':
  SysCls = 'clear'
elif sys.platform == 'win32' or sys.platform == 'dos' or sys.platform[0:5] == 'ms-dos':
  SysCls = 'cls'
else:
  SysCls = 'unknown'

face =   '''

        _____  _______ ______   ______  ____  _____     ____  
        \__  \ \_  __ \\____ \ /  ___/_/ ___\ \__  \   /    \               
         / __ \_|  | \/|  |_> >\___ \ \  \___ / __ \_|   |  \              
        (____  /|__|   |   __//____  > \___  >(____  /|___|  /              
             \/        |__|        \/      \/      \/      \/               


        by : fahri314


fahriguresci.com
arpscan.py version 1.0
arp scan for network security
Programmmer : Fahri Guresci
Edited time : 03-11-2017
fahri314[at]gmail[dot]com
________________________________________________________________________________
'''

option = '''
Usage: ./arpscan.py [options]
Options: -r, --target       <ip range>       |   network ip range
         -h, --help         <help>           |   print this help
                                                  
Example   : sudo python arpscan.py -r 192.168.1.0/24
'''

def MyFace() :
  os.system(SysCls)
  print face
  time.sleep(2)
  for x in range(0,10):
    print "\n"
    time.sleep(0.1)

def HelpMe() :
  os.system(SysCls)
  print option
  print "\nYour arguman count: ",len(sys.argv)
  sys.exit(1)

for arg in sys.argv:
  if arg.lower() == '-r' or arg.lower() == '--range':
    ip_range = sys.argv[int(sys.argv[1:].index(arg))+2]
  elif arg.lower() == '-h' or arg.lower() == '--help':
    HelpMe()
    sys.exit(1)
  elif len(sys.argv) != 2 and len(sys.argv) != 3:
    HelpMe()

MyFace()
os.system(SysCls)

ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range),timeout=2)
stop_time = datetime.now()
total_time = stop_time - start_time
ans.summary(lambda (s,r): r.sprintf("%Ether.src% %ARP.psrc%"))

file = open('mac_list.log', 'a+')
lines = file.readlines()
file_data = file.read()      # all item in s for search different IP address
file.close()

for snd,rcv in ans:
  for _ in lines:
    if _ == rcv.sprintf(r"%Ether.src% %ARP.psrc%" + "\n"):
      break
    if _.find(rcv.sprintf(r"%Ether.src%")) != -1:
      continue
  else:
    file = open('mac_list.log', 'r')
    file_data = file.read()
    file.close()
    if file_data.find(rcv.sprintf(r"%Ether.src%")) != -1:       # search mac address in s
      print "\n\nNew IP Operation"
      print "--------------------------------"
      answer = raw_input(rcv.sprintf(r"%ARP.psrc%") + " is set another IP address. Are you recording?(y or n): ")
      while(answer != "y" and answer != "n" and answer != "Y" and answer != "N"):
        answer = raw_input(rcv.sprintf(r"%ARP.psrc%") + " is set another IP address. Are you recording?(y or n): ")
      if answer == "y" or answer == "Y":
        for _ in lines:                                   # find old ip address and then change with new one
          if _.find(rcv.sprintf(r"%Ether.src%")):
            couple = _.split(" ")
            old_ip = couple[1]
        file = open('mac_list.log', 'r')
        file_data = file.read()
        file.close()
        file_data = file_data.replace(old_ip, rcv.sprintf(r"%ARP.psrc%"))
        print "\n***********\n"+ old_ip + "\n***********\n"
        file = open('mac_list.log', 'w')
        file.write(file_data)
        file.close()
    else:
      print "\n\nNew Device Operation"
      print "--------------------------------"
      answer = raw_input(rcv.sprintf(r"%ARP.psrc%") + " New device was detected. Are you recording?(y or n): ")
      while(answer != "y" and answer != "n" and answer != "Y" and answer != "N"):
        answer = raw_input(rcv.sprintf(r"%ARP.psrc%") + " New device was detected. Are you recording?(y or n): ")
      if answer == "y" or answer == "Y":
        file = open('mac_list.log', 'a+')
        file.write(rcv.sprintf(r"%Ether.src% %ARP.psrc%"+"\n"))
        file.close()

print "\n[*] Scan Complete!"
print "[*] Scan Duration: %s" %(total_time)
print "[+] Created file : 'mac_list.log'"