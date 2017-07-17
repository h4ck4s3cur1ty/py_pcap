import socket, binascii, struct
import time

sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
print "Waiting.."
pkt = sock.recv(2048)
print "received"

def hex2ip(hex_ip):
    addr_long = int(hex_ip,16)
    hex(addr_long)
    hex_ip = socket.inet_ntoa(struct.pack(">L", addr_long))
    return hex_ip

while len(pkt) > 0:

    print "Waiting.."
    pkt = sock.recv(2048)
    print "received"

    if(len(pkt)) > 54:
        ethHeader = pkt[0:14]
        ipHeader = pkt[14:34]
        tcpHeader = pkt[34:38]

	print 'dest mac : ' + ethHeader.encode('hex')[:12]
	print 'src mac : ' + ethHeader.encode('hex')[12:24]
	print 'type : ' + ethHeader.encode('hex')[24:28]
	
	print 'dest ip : ' + hex2ip(ipHeader.encode('hex')[24:32])
	print 'src ip : ' + hex2ip(ipHeader.encode('hex')[32:40])
	
	print 'dest port : ' + str(int(tcpHeader.encode('hex')[0:4], 16))
	print 'src port : ' + str(int(tcpHeader.encode('hex')[4:8], 16))


	length = int(ipHeader.encode('hex')[4:8], 16) + 14
	print 'length : ' + str(length)
	#print 'test' + 
	#print 'data : ' + length
	
	#print "from:  "+hex2ip(ipdata[0])+":"+tcpdata[0]+"    to:  "+hex2ip(ipdata[1])+":"+tcpdata[1]
	
    else:
        continue
