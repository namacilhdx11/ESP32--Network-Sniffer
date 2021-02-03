# ESP32--Network-Sniffer

This started as a Schoolprojekt but i found so interesting that i want to continue it a little until it might become a usefull tool.
Right now this thing can read out packages and identify different parts of it i want to make it able to reconstruct devices and Accses points in a Network.

it would like this to be shared and forked but also want to have some trace to this github. Thanks!

#### Programming diary i guess:

## Network Sniffer V2.01 d3.02
ive figured that there isnt much more to find in a association request so i went on again with the beacon... there i also have conflicting infos or at least infos that are unreadable to a point where my interpretation of them is conflikting. i also went into trouble with the esp32 virtual machine kinda thing i run into a lot of bugs currently as if that sequemnt of the code is getting too long

Type                                : Beacon
Channel                             : 6
Recieving/Destination(RA/DA) Adress : 26 18 1d f9 aa cf 
Transmitting Adress/ AP Mac (BSSID) : dc a6 32 dd 2b e8 
Source Adress (SA)                  : 33 33 00 00 00 fb 
Guru Meditation Error: Core  0 panic'ed (Interrupt wdt timeout on CPU0)
Core 0 register dump:
PC      : 0x4008476f  PS      : 0x00040034  A0      : 0x400014fa  A1      : 0x3ffbe1d0  
A2      : 0x00ff0000  A3      : 0x3ffbe8a8  A4      : 0x400d4a54  A5      : 0x0000ff00  
A6      : 0x00ff0000  A7      : 0xff000000  A8      : 0x00000000  A9      : 0x4008b2e0  
A10     : 0x3ffbebf8  A11     : 0x3f401751  A12     : 0x00000000  A13     : 0x00000000  
A14     : 0x00000000  A15     : 0xff000000  SAR     : 0x00000012  EXCCAUSE: 0x00000005  
EXCVADDR: 0x00000000  LBEG    : 0x400012c5  LEND    : 0x400012d5  LCOUNT  : 0xfffffff8  
Core 0 was running in ISR context:
EPC1    : 0x400014fa  EPC2    : 0x00000000  EPC3    : 0x00000000  EPC4    : 0x4008476f

Backtrace: 0x4008476f:0x3ffbe1d0 0x400014f7:0x3ffb4260 0x400d20a1:0x3ffb4270 0x400d212d:0x3ffb4290 0x400d1bd6:0x3ffb42b0 0x40132a1a:0x3ffb4490 0x4008f5cd:0x3ffb44b0 0x40088b7d:0x3ffb44f0

Core 1 register dump:
PC      : 0x40008544  PS      : 0x00060d34  A0      : 0x80090d05  A1      : 0x3ffb1f20  
A2      : 0x00005dc0  A3      : 0x71972f9b  A4      : 0x00000003  A5      : 0x3ffbf88c  
A6      : 0x00000000  A7      : 0x00000000  A8      : 0x80008547  A9      : 0x3ffb1f10  
A10     : 0x00005943  A11     : 0x00000001  A12     : 0x80088d90  A13     : 0x3ffb1e20  
A14     : 0x00000000  A15     : 0x3ffb0060  SAR     : 0x0000001d  EXCCAUSE: 0x00000005  
EXCVADDR: 0x00000000  LBEG    : 0x400029ac  LEND    : 0x400029cb  LCOUNT  : 0x00000000  

Backtrace: 0x40008544:0x3ffb1f20 0x40090d02:0x3ffb1f40 0x400d104d:0x3ffb1f60 0x400d27a1:0x3ffb1fb0 0x40088b7d:0x3ffb1fd0

Rebooting...

*interrupt timeout* <- that kinda goes over my head ... i guess or rather hope there are options to get around that, yet as i said again kinda stuck at the same frame but with different problems altho i still cant find an SSID in the beacon. ya kinda demotivates me xD so much for that





## Network Sniffer V2 d02.02
This is the Secound ov.r work of this thing. ive thrown out the listing part of it (for now) and reworked the intire package identifying and how packages are interpreted.
The previous way in wich there was a forloop for identifying if a package was new or known. and then having 2 times almost the same code for either
new macs or known macs was not very elegant. so for know i want to completly identify everything there is to identify about a package and then make it look for things wich
can be interpreted together basicly finding ssids to macs maybe even draw a network with who is with whom and stuff... also ive reworked the channel hooping just enough so
that i can for now, focus on one channel and one channel only. that makes seeing connections and therefore understanding wifi myself way easyer.

also with beacons ive run into a kinda dead end for now, (cant find any ssid part in it although it should be there) so i dicided to go thourgh packages in the order of most commenly seen. <- if that even makes sence.
so association request were the most commenly seen packages and they got me way more forward then beacons although that also kinda shook up my understanding of requests and respones but i will look into it. now an SSID *can be read wich was a great step forward* and that kinda motivates me.

when im done with associatoin requests, beacons are next anyway ... i find it frustrating how hard it is, to find info on that IEEEE standart because it seems not to be free wich tbh is really weird to me ... im kinda not sure what or who to trust, because sometimes infos conflict.
