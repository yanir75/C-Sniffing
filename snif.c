#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define PCKT_LEN 1024
#define IP_LEN 20


// IP header
struct sniff_ip 
{
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


struct sniff_icmp{
	#define ICMP_ECHO_REQ 8
	#define ICMP_ECHO_RES 0
	#define ICMP_HDR_LEN 4
 	unsigned char icmp_type;
 	unsigned char icmp_code;
 	unsigned short icmp_cksum;		/* icmp checksum */
 	unsigned short icmp_id;				/* icmp identifier */
 	unsigned short icmp_seq;			/* icmp sequence number */
};
void got_packet(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet);
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip proto ICMP";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("any", PCKT_LEN, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}



void got_packet(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet)
{
 	struct sniff_ethernet* eth;
	struct sniff_ip* ip;
	struct sniff_icmp* icmp;
	eth = (struct sniff_ethernet*)(packet);
	ip=(struct sniff_ip*)(packet+SIZE_ETHERNET);
	icmp = (struct sniff_icmp*)(packet+SIZE_ETHERNET+IP_LEN);
	printf("%s\n",inet_ntoa(ip->ip_src));
	printf("%s\n",inet_ntoa(ip->ip_dest));
	printf("%d\n",icmp->icmp_type);
	printf("%d\n",icmp->icmp_code);
}
