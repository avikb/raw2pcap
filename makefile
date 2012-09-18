default:
	g++ main.cpp -Wall -ggdb -lpcap -o raw2pcap

final:
	g++ main.cpp -Wall -O2 -lpcap -o raw2pcap
