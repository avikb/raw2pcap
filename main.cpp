#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <pcap/pcap.h>
#include <netinet/ip.h>

using namespace std;


int main(int argc, char *argv[]) {
	if(argc < 2) {
		cout << "Usage: " << argv[0] << " <raw_file> <pcap_file>" << endl;
		return -1;
	}
	
	ifstream in(argv[1], ios::binary);
	if(!in) {
		cout << "can't open input file '" << argv[1] << "'" << endl;
		return -1;
	}
	
	string outfile = (argc == 3 ? std::string(argv[2]) : std::string(argv[1])+".pcap");

	pcap_t *pcap = pcap_open_dead(DLT_RAW, 65535);
	
	pcap_dumper_t *out = pcap_dump_open(pcap, outfile.c_str());
	if(!out) {
		cout << "can't open output file '" << outfile << "' for pcap dump" << endl;
		return -1;
	}

	while(in) {
		// read ip header
		struct ip ip;
		in.read(reinterpret_cast<char*>(&ip), sizeof(struct ip));
		uint16_t iplen = ntohs(ip.ip_len); // full ip packet length include ip header

		// read rest of ip packet
		vector<char> vec(iplen);
		memcpy(&vec[0], &ip, sizeof(struct ip));
		in.read(&vec[sizeof(struct ip)], iplen - sizeof(struct ip));

		pcap_pkthdr phead;
		memset(&phead, 0, sizeof(pcap_pkthdr));
		phead.caplen = iplen;
		phead.len = iplen;
		
		pcap_dump(reinterpret_cast<u_char*>(out), &phead, reinterpret_cast<const u_char*>(&vec[0]));
	}
	
	pcap_dump_close(out);
	
	return 0;
}
