# Matala-tikshoret

The project is about demonstrating sniffing packets.
We will sniff specifically ICMP packets and will print their information.

Snif will create a raw socket listening to all incoming traffic and will parse and print the ICMP packets.
Both packets going into the network and from the network.

Myping will send a icmp request to google for the sniffer to print.  
It will do that in raw socket as well.


# How to use
gcc is required
First lets compile
```
gcc -o myping myping.cpp -lstdc++
```
```
gcc -o snif snif.c
```
Activate sniffer
```
./snif
```
Activate pinger
```
./myping
```
