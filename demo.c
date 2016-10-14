#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <errno.h>

//using namespace std;
#define MAXMSG 65535

#define MSG_OFF 10         //the offset of the whole message
#define MSG_DBUG

int sockfd;

enum tcp_flag{INV,ACK,SYN,FIN};

int msg_handle(uint8_t* msg,int size);
int ether_handle(struct ether_header* eth_header);
int ip_handle(struct ip* ip_header);
enum tcp_flag tcp_handle(struct tcphdr* tcp_header);
int mac_matching(struct ether_header* eth_header);
int ip_matching(struct ip* ip_header);
int ip_tcp_proto(struct ip* ip_header);
int tcp_syn(struct tcphdr* tcp_header);
int tcp_fin(struct tcphdr* tcp_header);
int tcp_ack(struct tcphdr* tcp_header);
int tcp_src_port(struct tcphdr* tcp_header);
int tcp_dst_port(struct tcphdr* tcp_header);
void send_msg(char* data,int size);

void conn_establish(int port);
void conn_close();

int main() {
	int num;
	while (scanf("%d",&num)) {
		uint8_t str[MAXMSG];
		struct ether_header *eth_header;  
		struct ip* ip_header;
		struct tcphdr* tcp_header;

		int i;
		for(i=0; i<num; i++) {
			int input;
			scanf("%d",&input);
			str[i]=input;
		}
	msg_handle(str,num);
}


	return 0;
}

int msg_handle(uint8_t* msg,int size) {

	int ret = 1;
	int ip_header_size = 0;
	int all_header_size = 0;
	enum tcp_flag type = INV;
	struct ether_header *eth_header;
	struct ip* ip_header;
	struct tcphdr* tcp_header;
	char* real_data;

	if(size < MSG_OFF) {

		ret = 0;
		goto msg_handle_exit;
	}

	if(size < MSG_OFF + sizeof(struct ether_header)) {

		ret = 0;
		goto msg_handle_exit;
	}

	eth_header = (struct ether_header*)(msg+MSG_OFF);
	ret = ether_handle(eth_header);

	if(!ret) {

		goto msg_handle_exit;
	}

	if(size < MSG_OFF + sizeof(struct ether_header) + sizeof(struct ip)) {

		ret = 0;
		goto msg_handle_exit;
	}

	ip_header = (struct ip*)(msg+MSG_OFF+sizeof(struct ether_header));
	ip_header_size = 4 * (ip_header->ip_hl & 0x0F);       //get the length of ip header

	ret = ip_handle(ip_header);

	if(!ret) {

		goto msg_handle_exit;
	}

	tcp_header = (struct tcphdr*)(msg+MSG_OFF+ip_header_size+sizeof(struct ether_header));

	type = tcp_handle(tcp_header);

	if(type==ACK) {

		all_header_size=4*(tcp_header->th_off & 0x0F)+MSG_OFF+ip_header_size+sizeof(struct ether_header);
		if(all_header_size < size) {
			real_data = (char*)(msg+all_header_size);

			//todo, forward to backup
			send_msg(real_data,size - all_header_size);
			printf("%s\n",real_data);
		}
	}


	return ret;


msg_handle_exit:

#ifdef MSG_DBUG
	printf("The information of this packet can be ignored\n");
#endif

	return ret;

}

void conn_establish(int port) {
	struct sockaddr_in    servaddr;
    const char* dst_addr = "127.0.0.1";

    if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
    	printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);
    	exit(0);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    if( inet_pton(AF_INET, dst_addr, &servaddr.sin_addr) <= 0){
    	printf("inet_pton error for");
    	exit(0);
    }

    if( connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0){
    	printf("connect error: %s(errno: %d)\n",strerror(errno),errno);
    	exit(0);
    }
}

void send_msg(char* data,int size) {

    if( write(sockfd, data, size) < 0)
    {
    printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
    exit(0);
    }
}

void conn_close() {
	close(sockfd);
}



int ether_handle(struct ether_header* eth_header) {
	int ret = 1;
	ret=(ntohs(eth_header->ether_type) == ETHERTYPE_IP);
	if(!ret) {

#ifdef MSG_DBUG
		printf("This packet is not a ip packet\n");
#endif

		goto ether_handle_exit;
	}
	ret=mac_matching(eth_header);
	if(!ret) {

#ifdef MSG_DBUG
		printf("Destination Mac Address is not correct\n");
#endif

		goto ether_handle_exit;
	}

ether_handle_exit:
	return ret;
}

int ip_handle(struct ip* ip_header) {

	int ret = 1;

	ret = ip_matching(ip_header);

	if(!ret) {

#ifdef MSG_DBUG
		printf("Ip Address is not correct\n");
#endif
		return ret;
	}

	ret = ip_tcp_proto(ip_header);

	if(!ret) {

#ifdef MSG_DBUG
		printf("Ip Packet does not include TCP header\n");
#endif
		return ret;
	}

	return ret;
}

enum tcp_flag tcp_handle(struct tcphdr* tcp_header) {

	int ret = 1;
	int dst_port = 0;
	int src_port = 0;
	enum tcp_flag type = INV;

	dst_port = tcp_dst_port(tcp_header);

	//todo ensure the port is critical applications' port
	if(dst_port!=6379) {

#ifdef MSG_DBUG
		printf("Packet of port %d is not critical applications' packet\n",dst_port);
#endif		
		goto tcp_handle_exit;
	}

	//src_port maybe useful in the following 
	src_port = tcp_src_port(tcp_header);

	ret = tcp_syn(tcp_header);

	if(ret) {

#ifdef MSG_DBUG
		printf("TCP Connection Established Process\n");
#endif
		//todo, create a connection for backup
		conn_establish(dst_port);
		type = SYN;
		goto tcp_handle_exit;
	}

	ret = tcp_fin(tcp_header);

	if(ret) {

#ifdef MSG_DBUG
		printf("TCP Connection Closed Process\n");
#endif
		//todo, close the connection
		conn_close();
		type = FIN;
		goto tcp_handle_exit;
	}

	ret = tcp_ack(tcp_header);

	if(ret) {

#ifdef MSG_DBUG
		printf("This tcp message is valid\n");
#endif
		//todo, close the connection
		type = ACK;
		goto tcp_handle_exit;
	}
	else {

#ifdef MSG_DBUG
		printf("This message is invalid, drop\n");
#endif
		//todo, close the connection
		type = INV;
		goto tcp_handle_exit;		
	}

tcp_handle_exit:

	return type;

}

int mac_matching(struct ether_header* eth_header) {

	int ret = 1;

	u_char* dhost = eth_header->ether_dhost;
	u_char mac[ETHER_ADDR_LEN]={0x52,0x54,0x00,0xd5,0xa0,0x99};

	int i;
	for(i=0; i<ETHER_ADDR_LEN; i++) {
		if(*(dhost+i)!=mac[i]) {
			ret = 0;
			return ret;
		}
	}

	return ret;
}

int ip_matching(struct ip* ip_header) {

	struct in_addr dst_ip_addr=ip_header->ip_dst;

	int ret = (dst_ip_addr.s_addr==inet_addr("10.22.1.42"));

	return ret;
}

int ip_tcp_proto(struct ip* ip_header) {
	int tcp_proto = 1;

	tcp_proto = (ip_header->ip_p==0x06);

	return tcp_proto;
}

int tcp_syn(struct tcphdr* tcp_header) {

	int ret = 1;

	ret = ((tcp_header->th_flags & TH_SYN) == TH_SYN);

	return ret;
}

int tcp_fin(struct tcphdr* tcp_header) {

	int ret = 1;

	ret = ((tcp_header->th_flags & TH_FIN) == TH_FIN);

	return ret;
}

int tcp_ack(struct tcphdr* tcp_header) {

	int ret = 1;

	ret = ((tcp_header->th_flags & TH_ACK) == TH_ACK);

	return ret;
}

int tcp_src_port(struct tcphdr* tcp_header) {

	int port = 0;

	port = ntohs(tcp_header->th_sport);

	return port;
}

int tcp_dst_port(struct tcphdr* tcp_header) {

	int port =0;

	port = ntohs(tcp_header->th_dport);

	return port;
}
