arp_poison: arp_poison.o InitPcap.o GetNetworkInfo.o AttackInfo.o
	gcc -pthread -o arp_poison arp_poison.o InitPcap.o GetNetworkInfo.o AttackInfo.o -lpcap

arp_poison.o: arp_poison.c
	gcc -c -o arp_poison.o arp_poison.c -lpcap

InitPcap.o: InitPcap.c
	gcc -pthread -c -o InitPcap.o InitPcap.c -lpcap

GetNetworkInfo.o: GetNetworkInfo.c
	gcc -c -o GetNetworkInfo.o GetNetworkInfo.c

AttackInfo.o: AttackInfo.c
	gcc -c -o AttackInfo.o AttackInfo.c

clean:
	rm arp_poison arp_poison.o InitPcap.o GetNetworkInfo.o AttackInfo.o
