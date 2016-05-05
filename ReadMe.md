#Filtering services by Hypervisor
----------------------------------

## Interface for Middleboxes:
-----------------------------
#### Acronyms used:
...................
R - register a middlebox
A - Add services for registered MB
D - Delete services for registered MB
X - Quit MB registration
I - current IP header filters' status
M - current MAC header filters' status 
T - current TCP header filters' status
s - srcIP / srcMAC / srcPort
d - dstIP / dstMAC /dstPort
t - tos
p - protocol / ethprotocol


#### Explanation: current IP/MAC/TCP filters' status:
.....................................................
Bit - j = 0, filter corrosponding to that bit is OFF
		= 1, filter corrosponding to that bit is ON

For IP filters' status,
bit 0 - srcIP(LSB), bit 1 - dstIP, bit 2 - tos, bit 3 - protocol(MSB)
value of I should be: [0,15]

For MAC filters' status,
bit 0 - srcMAC(LSB), bit 1 - dstMAC, bit 2 - tos, bit 3 - ethprotocol(MSB)
value of M should be: [0,7]

For TCP filters' status,
bit 0 - srcport(LSB), bit 1 - dstport(MSB)
value of I should be: [0,3]


#### Explanation: command formats:
..................................
R <MACaddress> <IPaddress> 
A <MACaddress> {[I/M/T] value} {s value} {d} {t value} {p value}
D <MACaddress> {[I/M/T] value} {s} {d} {t} {p}
X <MACaddress>


#### Examples:
..............
R 12:13:14:15:16:17 10.129.126.15 
It registers a middlebox having MAC address specified in the command.

A 12:13:14:15:16:17 M 5 s 1:2:3:4:5:6 p 8
It enables filtering on source MAc address and ethernet protocol fields of packets coming for the specified middlebox.

D 12:13:14:15:16:17 M 4 s
It removes source MAC address filter on the packets coming for the specified middlebox.

X 12:13:14:15:16:17
It cancels registration of the specified middlebox.
