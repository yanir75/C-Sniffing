#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

/* IP Header */
typedef struct sniff_ip
{
	unsigned ip_vhl;			   /* version << 4 | header length >> 2 */
	unsigned ip_tos;			   /* type of service */
	unsigned ip_len;			   /* total length */
	unsigned ip_id;				   /* identification */
	unsigned ip_off;			   /* fragment offset field */
#define IP_RF 0x8000			   /* reserved fragment flag */
#define IP_DF 0x4000			   /* dont fragment flag */
#define IP_MF 0x2000			   /* more fragments flag */
#define IP_OFFMASK 0x1fff		   /* mask for fragmenting bits */
	unsigned ip_ttl;			   /* time to live */
	unsigned ip_p;				   /* protocol */
	unsigned short ip_sum;		   /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
}iph;
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)
#define ETH_SIZE 14
#define ETHER_ADDR_LEN 6
/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};


void got_packet(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet)
{
   iph* ip;
   ip=(iph*)(packet+ETH_SIZE);
   printf("SRC: %s\nDEST: %s\n",inet_ntoa(ip->src),inet_ntoa(ip->dst));
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip proto ICMP";
  bpf_u_int32 net;
  char * dev="eth0"

  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}
