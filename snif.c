#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet){
    printf("Got a packet");
}

int main()
{
    pcap_t *handle;
    char errbuff[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "icmp";
    struct bpf_program filter;
    bpf_u_int32 subnet_mask;
    bpf_u_int32 net;
    
    if(pcap_lookupnet("any", &net, &subnet_mask, errbuff)==1)
    {
        printf("%s\n",errbuff);
        exit(1);
    }
    handle = pcap_open_live("any",BUFSIZ,0,1000,errbuff);
    if(handle == NULL)
    {
        printf("%s\n",errbuff);
        exit(1);
    }
    if(pcap_compile(handle,&filter,filter_exp,1,net)==-1)
        {
            printf("bad filter\n");
            exit(1);
        }
    if(pcap_setfilter(handle,&filter)==-1)
    {
        printf("failed to set filter");
        exit(1);
    }
    pcap_loop(handle,-1,got_packet,NULL);
    return 0;

}
