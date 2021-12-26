#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#ifndef SIZE_ETHERNET
#define SIZE_ETHERNET 14
#endif
#define PCKT_LEN 1024





/* IP header */
typedef struct sniff_ip 
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
}iph;
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)



typedef struct sniff_icmp{
	#define ICMP_ECHO_REQ 8
	#define ICMP_ECHO_RES 0
	#define ICMP_HDR_LEN 4
 	unsigned char icmp_type;
 	unsigned char icmp_code;
 	unsigned short icmp_cksum;		/* icmp checksum */
 	unsigned short icmp_id;				/* icmp identifier */
 	unsigned short icmp_seq;			/* icmp sequence number */
}icmph;

void got_packet(unsigned char* buffer, int size)
{
    iph *ip;
    ip= (iph*)(buffer+SIZE_ETHERNET);
    if(ip->ip_p==1)	
    {	    icmph *icmp;
            icmp=(icmph*)(buffer+SIZE_ETHERNET+20);
     if(icmp->icmp_id==18){
	    printf("SRC:%s\n",inet_ntoa(ip->ip_src));
	    printf("DEST:%s\n",inet_ntoa(ip->ip_dst));
	    printf("Type: %d\n",icmp->icmp_type);
	    printf("Code: %d\n\n",icmp->icmp_code);
     }
    }
	
	


    
}

int main(int argc, char *argv[]) {

    int sock;
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("could not create socket");
        return -1;
    }

    struct packet_mreq mr;
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
    struct sockaddr dest_in;
    socklen_t len = sizeof(dest_in);
    char buf[1024];
    while(1) {
        bzero(buf, 1024);
        int rc = recvfrom(sock, buf, ETH_FRAME_LEN, 0, &dest_in, &len);
        got_packet(buf, rc);
    }
}
