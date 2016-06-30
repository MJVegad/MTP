#Offloading Middlebox Services To Hypervisors For Efficient Network Function VIrtualization

###Host Setup
--------------
1) Run ./bridge_setup.sh.<br/>
2) Start a virtual machine,<br/>
	qemu-system-x86_64 sandbox.img -m 2048 -enable-kvm -device ivshmem,shm=ivshmem,size=1 -net bridge,br=kvmbr0 -net nic,model=virtio<br/>
3) Provide the filtering and the load balancer services at the hypervisor.<br/>
	sudo insmod bfilter.ko<br/>
	sudo insmod bloadbal.ko<br/>
4) Periodically listen to the middleboxes,<br/>
	gcc readSHM.c -lrt<br/>
	sudo ./a.out<br/>

###Guest Setup
---------------
1) Run ./StartMB.sh.<br/>
2) Now register or quit hypervisor services using commands defined below,<br/>
	sudo ./a.out -w "@....command.....@"<br/>
	

###Commands For Filtering / Load balancer services
---------------------------------------------------

#### Interface for Middleboxes:
#### Acronyms used:
R - register a middlebox <br/>
F - Firewall Services <br/>
L - Load balancer services <br/>
A - Add services for registered MB<br/> 
D - Delete services for registered MB<br/>
X - Quit MB registration<br/>
I - current IP header filters' status<br/>
M - current MAC header filters' status <br/>
T - current TCP header filters' status<br/>
s - srcIP / srcMAC / srcPort<br/>
d - dstIP / dstMAC /dstPort<br/>
t - tos<br/>
p - protocol / ethprotocol<br/>


#### Explanation: current IP/MAC/TCP filters' status:
Jth bit = 0, filter corrosponding to that bit is OFF<br/>
Jth bit = 1, filter corrosponding to that bit is ON<br/>
<br/>
For IP filters' status,<br/>
bit 0 - srcIP(LSB), bit 1 - dstIP, bit 2 - tos, bit 3 - protocol(MSB)<br/>
value of I should be: [0,15]<br/>
<br/>
For MAC filters' status,<br/>
bit 0 - srcMAC(LSB), bit 1 - dstMAC, bit 2 - tos, bit 3 - ethprotocol(MSB)<br/>
value of M should be: [0,7]<br/>
<br/>
For TCP filters' status,<br/>
bit 0 - srcport(LSB), bit 1 - dstport(MSB)<br/>
value of I should be: [0,3]<br/>


#### Explanation: command formats:<br/>
R F {MACaddress} {IPaddress} <br/>
R L {MACaddress} {IPaddress} {balancetype} {srcip} {dstip}
A {MACaddress} {[I/M/T] value} {s value} {d} {t value} {p value}<br/>
D {MACaddress} {[I/M/T] value} {s} {d} {t} {p}<br/>
X {MACaddress}<br/>


#### Examples:
R L 12:13:14:15:16:17 10.129.126.15 0 10.129.126.17<br/>
It registers a middlebox having MAC address specified in the command for load balancer services and redirects the traffic to the destination address specified. 
<br/>
R F 12:13:14:15:16:17 10.129.126.15 <br/>
It registers a middlebox having MAC address specified in the command for firewall services.<br/>
<br/>
A 12:13:14:15:16:17 M 5 s 1:2:3:4:5:6 p 8<br/>
It enables filtering on source MAc address and ethernet protocol fields of packets coming for the specified middlebox.<br/>
<br/>
D 12:13:14:15:16:17 M 4 s<br/>
It removes source MAC address filter on the packets coming for the specified middlebox.<br/>
<br/>
X 12:13:14:15:16:17 F<br/>
It cancels registration of the specified middlebox.<br/>


