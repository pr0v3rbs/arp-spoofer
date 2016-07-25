arp_poison: arp_poison.o PcapManager.o GetNetworkInfo.o AttackInfo.o Print.o
	gcc -pthread -o arp_poison arp_poison.o PcapManager.o GetNetworkInfo.o AttackInfo.o Print.o -lpcap

arp_poison.o: arp_poison.c
	gcc -c -o arp_poison.o arp_poison.c -lpcap

InitPcap.o: PcapMnager.c
	gcc -pthread -c -o PcapManager.o PcapManager.c -lpcap

GetNetworkInfo.o: GetNetworkInfo.c
	gcc -c -o GetNetworkInfo.o GetNetworkInfo.c -lpcap

AttackInfo.o: AttackInfo.c
	gcc -c -o AttackInfo.o AttackInfo.c

Print.o: Print.c
	gcc -c -o Print.o Print.c

clean:
	rm arp_poison arp_poison.o PcapManager.o GetNetworkInfo.o AttackInfo.o Print.o
