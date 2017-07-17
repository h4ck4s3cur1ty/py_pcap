import socket
import binascii
import struct
import time

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
print "Waiting.."
packet = s.recv(2048)
print "received"

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
	
	print '-'*40

        print '[*]length : ' + str(T_len)

	print '-'*40

	dest_macadr = ethHeader.encode('hex')[:12]
        print '[*]dest mac : ' + "%s:%s:%s:%s:%s:%s"%(dest_macadr[0:2], dest_macadr[2:4], dest_macadr[4:6], dest_macadr[6:8], dest_macadr[8:10], dest_macadr[10:12])
        src_macadr = ethHeader.encode('hex')[12:24]
        print '[*]src mac : ' + "%s:%s:%s:%s:%s:%s"%(src_macadr[0:2], src_macadr[2:4], src_macadr[4:6], src_macadr[6:8], src_macadr[8:10], src_macadr[10:12])

	print '-'*40
	#print '[*]type : ' + ethHeader.encode('hex')[24:28]	
	print '[*]dest ip : ' + hex2ip(ipHeader.encode('hex')[24:32])
	print '[*]src ip : ' + hex2ip(ipHeader.encode('hex')[32:40])
	
	print '-'*40
	
	print '[*]dest port : ' + str(int(tcpHeader.encode('hex')[0:4], 16))
	print '[*]src port : ' + str(int(tcpHeader.encode('hex')[4:8], 16))
	
	print '-'*40
	
	print '[*]data : ' + packet.encode('hex')[T_len:]
	
	print '-'*40
	
    else:
        continue




