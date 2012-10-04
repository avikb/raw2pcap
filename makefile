BIN=raw2pcap

default: final

final:
	g++ main.cpp -Wall -O2 -lpcap -o ${BIN}

debug:
	g++ main.cpp -Wall -ggdb -lpcap -o ${BIN}

install: final
	cp ${BIN} /usr/bin/
