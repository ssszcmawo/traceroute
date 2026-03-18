#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>

#define PACKET_LEN_DEFAULT_NUM 56
#define MAX_TTL 30
#define DEFAULT_TRACEROUTE_PORT 33434

static int ttl = 0;

static unsigned short ip_checksum(unsigned short* buff, int _16bitword);

int main(int argc, char* argv[])
{
    int send_sockfd, recv_sockfd;
    unsigned char* data;
    size_t data_len = PACKET_LEN_DEFAULT_NUM; size_t total_len = 0;

    char recv_buffer[PACKET_LEN_DEFAULT_NUM];

    struct iphdr* iph;
    struct udphdr* udph;
    struct sockaddr_in dest_addr;
    struct sockaddr_in recv_addr;
    socklen_t recv_len = sizeof(recv_addr);

    if (argc < 2)
    {
	fprintf(stderr, "Usage: %s <host>\n", argv[0]);
	return -1;
    }

    data = (unsigned char*) malloc(data_len);

    if (!data)
    {
	fprintf(stderr, "Could not allocate memory: data\n");
	return -1;
    }

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = 0;

    if (inet_pton(AF_INET, argv[1], &dest_addr.sin_addr) <= 0)
    {
	fprintf(stderr, "inet pton error\n");
	exit(EXIT_FAILURE);
    }

    iph = (struct iphdr*) (data);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->id = htons(getpid() & 0xFFFF);
    iph->protocol = 17;
    iph->check = 0;
    iph->saddr = inet_addr("10.85.53.148");
    iph->daddr = dest_addr.sin_addr.s_addr;

    total_len += sizeof(struct iphdr);

    udph = (struct udphdr*) (data + sizeof(struct iphdr));

    udph->source = htons(49167);
    udph->check = 0;

    total_len += sizeof(struct udphdr);

    udph->len = htons((total_len - sizeof(struct iphdr)));

    iph->tot_len = htons(total_len);

    send_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    recv_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (send_sockfd < 0 || recv_sockfd < 0)
    {
	perror("socket error");
	exit(1);
    }

    int one = 1;
    setsockopt(send_sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    ssize_t sendto_len = 0;
    ssize_t recvfrom_len = 0;

    for(ttl = 1; ttl < MAX_TTL; ttl++)
    {
	iph->ttl = ttl;
	udph->dest = htons(DEFAULT_TRACEROUTE_PORT + ttl);

	iph->check = ip_checksum((unsigned short*)iph, sizeof(struct iphdr)/2);

	struct timeval start, end, tv;

	tv.tv_sec = 1;
	tv.tv_usec = 0;

	setsockopt(recv_sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	gettimeofday(&start, NULL);

	if ((sendto_len = sendto(send_sockfd, data, ntohs(iph->tot_len), 0,
			(struct sockaddr*)&dest_addr ,sizeof(dest_addr))) <= 0)
	{
	    perror("sendto");
	    exit(1);
	}

	if ((recvfrom_len = recvfrom(recv_sockfd, recv_buffer, sizeof(recv_buffer), 0,
			(struct sockaddr*)& recv_addr, &recv_len)) < 0)
	{
	    for (int try = 0; try < 3; try++)
	    {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
		{
		    printf("* ");
		}
	    }
	    printf("\n");
	}

	gettimeofday(&end, NULL);

	long rtt = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;

	struct iphdr* ip_reply = (struct iphdr*)recv_buffer;
	struct icmphdr* icmp_reply = (struct icmphdr*)(recv_buffer + ip_reply->ihl*4);

	struct iphdr* orig_ip = (struct iphdr*)(icmp_reply + 1);
	struct udphdr* orig_udp = (struct udphdr*)((char*)orig_ip + orig_ip->ihl*4);

	if (ntohs(orig_udp->dest) != DEFAULT_TRACEROUTE_PORT + ttl)
	    continue;

	if (icmp_reply->type == ICMP_TIME_EXCEEDED)
	{
	    printf("%d %s %.3ld ms\n", ttl, inet_ntoa(recv_addr.sin_addr), rtt);
	}
	else if (icmp_reply->type == ICMP_DEST_UNREACH && icmp_reply->code == ICMP_PORT_UNREACH)
	{
	    printf("%d %s %.3ld ms (destination reached)\n", ttl, inet_ntoa(recv_addr.sin_addr), rtt);
	    break;
	}
    }

    free(data);
    close(send_sockfd);
    close(recv_sockfd);
    return 0;
}

static unsigned short ip_checksum(unsigned short* buff, int _16bitword)
{
    unsigned long sum;

    for (sum = 0; _16bitword > 0; _16bitword--)
    {
	sum += htons(*(buff)++);
	sum = ((sum >> 16) + (sum & 0xFFFF));
	sum += (sum >> 16);
    }

    return (unsigned short)(~sum);
}
