'''
Coursera:
- Software Defined Networking (SDN) course
-- Programming Assignment: Layer-2 Firewall Application

Professor: Nick Feamster
Teaching Assistant: Arpit Gupta
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
''' Add your imports here ... '''
import csv

import pox.lib.packet as pkt

rowCount = 0

log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]  

''' Add your global variables here ... '''


class Firewall (EventMixin):

    def __init__ (self):
        print "INit it \n" 
        print "INit it \n" 
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    def _handle_ConnectionUp (self, event):    
        ''' Add your logic here ... '''
        #import file 
        print "Connection Up "
        rowCount = 0

        with open(policyFile, 'rb') as csvfile:
            bbpolicys = csv.reader(csvfile, delimiter=',', quotechar='|' )
            for row in bbpolicys:
                rowCount = rowCount + 1
                if rowCount > 1:
                   print "thing1" + row[0]
                   print "thing2" + row[1]
                   print "thing 3" + row[2]
                   print "----"
                   #parsed = split(row)
                   print "&& ".join(row)

                   msg = of.ofp_flow_mod()
                   msg.match = of.ofp_match()
                   #msg.match.dl_type = pkt.ethernet.IP_TYPE
                   #msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
                   #msg.match.nw_dst = IP_BROADCAST
                   msg.match.dl_src = EthAddr(row[1]) 
                   msg.match.dl_dst = EthAddr(row[2]) 
                   msg.priority = 10 
                   print row[1]
                   print pkt.dhcp.SERVER_PORT

                   #msg.match.tp_src = pkt.dhcp.SERVER_PORT
                   #msg.match.tp_dst = pkt.dhcp.SERVER_PORT
                   msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
                   #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
                   event.connection.send(msg)

#                   fm = of.ofp_flow_mod()
#                   fm.match = of.ofp_match()
#                   fm.match.dl_src = row[1]
#                   fm.match.dl_dst = row[2]
#                   fm.actions.append(of.ofp_action_output(port =  of.OFPP_NONE)) 
#                   event.connection.send(fm)

    
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
