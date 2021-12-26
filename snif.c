#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#define SIZE_ETHERNET 14
#define PCKT_LEN 1024
#define IP_LEN 20

/* IP header */
struct sniff_ip
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
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

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

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *handle){
    struct sniff_ip* ip;
    struct sniff_icmp* icmp;
    ip = (struct sniff_ip*)(handle+14);
    printf("%s",inet_ntoa(ip->ip_src));
	printf("%s",inet_ntoa(ip->ip_dst));
    printf("Got a packet");
}

int main()
{
    pcap_t *handle;
    char errbuff[PCAP_ERRBUF_SIZE];
    //char filter_exp[] = "ip proto ICMP";
    struct bpf_program filter;
    bpf_u_int32 net;
    
    handle = pcap_open_live("eth0",PCKT_LEN,1,1000,errbuff);
    if(handle == NULL)
    {
        printf("%s\n",errbuff);
        exit(1);
    }
    if(pcap_compile(handle,&filter,"icmp",0,net)==-1)
        {
            printf("bad filter\n");
            exit(1);
        }
    if(pcap_setfilter(handle,&filter)==-1)
    {
        printf("failed to set filter");
        exit(1);
    }
    pcap_loop(handle,0,got_packet,NULL);
    return 0;

}
