import socket
import binascii
import struct
import time

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
print "Waiting.."
packet = s.recv(2048)
print "received"

def HexToByte(hexStr):
    bytes = []
    hexStr = ''.join( hexStr.split(" ") )
    for i in range(0, len(hexStr), 2):
        bytes.append( chr( int (hexStr[i:i+2], 16 ) ) )

    return ''.join( bytes )

def hex2ip(hex_ip):
    addr_long = int(hex_ip,16)
    hex(addr_long)
    hex_ip = socket.inet_ntoa(struct.pack(">L", addr_long))
    return hex_ip

while len(packet) > 0:

    print "Waiting.."
    packet = s.recv(2048)
    print "received"

    if(len(packet)) > 56:
        ethHeader = packet[0:14]
        ipHeader = packet[14:34]
        tcpHeader = packet[34:50]
	
	ipH_len = int(ipHeader.encode('hex')[4:8], 16)
	T_len =  ipH_len + 14 
	tcpH_len = (int(tcpHeader.encode('hex')[24:26],16)/4)*2
        print '[*]length : ' + str(T_len)
	
	print '[*]dest mac : ' + ethHeader.encode('hex')[:12]
	print '[*]src mac : ' + ethHeader.encode('hex')[12:24]
	print 'type : ' + ethHeader.encode('hex')[24:28]
	
	print '[*]dest ip : ' + hex2ip(ipHeader.encode('hex')[24:32])
	print '[*]src ip : ' + hex2ip(ipHeader.encode('hex')[32:40])
	
	print '[*]dest port : ' + str(int(tcpHeader.encode('hex')[0:4], 16))
	print '[*]src port : ' + str(int(tcpHeader.encode('hex')[4:8], 16))
	#print 'test : ' + str(tcpH_len)
	#print 'test222 : ' + str(T_len)
	#data_len = (T_len) - (14 + ipH_len + tcpH_len) 
	#print '[*]data : ' + packet.encode('hex')[:]
	print '[*]data : ' + packet.encode('hex')[T_len:]
	#print 'test' + 
	#print 'data : ' + length
	
	#print "from:  "+hex2ip(ipdata[0])+":"+tcpdata[0]+"    to:  "+hex2ip(ipdata[1])+":"+tcpdata[1]
	
    else:
        continue




