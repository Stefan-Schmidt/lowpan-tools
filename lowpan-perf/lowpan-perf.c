/*
 * Linux IEEE 802.15.4 performance measurement
 *
 * Copyright (C) 2011 Stefan Schmidt <stefan@datenfreihafen.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "ieee802154.h"

#include <netlink/netlink.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "nl802154.h"
extern struct nla_policy ieee802154_policy[IEEE802154_ATTR_MAX + 1];

#define MAX_PAYLOAD_LEN 115

#define MODE_ROUNDTRIP	1
#define MODE_THROUGHPUT	2
#define MODE_BOTH	3

#define PACKET_CONFIG		1
#define PACKET_ROUNDTRIP	2
#define PACKET_THROUGHPUT	3

#ifdef HAVE_GETOPT_LONG
static const struct option perf_long_opts[] = {
	{ "server", required_argument, NULL, 's' },
	{ "client", required_argument, NULL, 'c' },
	{ "packets", required_argument, NULL, 'p' },
	{ "length", required_argument, NULL, 'l' },
	{ "roundtrip", no_argument, NULL, 'r' },
	{ "throughput", no_argument, NULL, 't' },
	{ "version", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ NULL, 0, NULL, 0 },
};
#endif

struct config {
	char packet_len;
	int packets;
	long dst_addr;
	long src_addr;
	int pan_id;
	char server;
	char mode;
	char packet_type;
};

extern char *optarg;

void usage(const char *name) {
	printf("Usage: %s OPTIONS\n"
	"OPTIONS:\n"
	"--server |-s client address\n"
	"--client | -c server address\n"
	"--packets | -p number of packets\n"
	"--length | -l packet length\n"
	"--roundtrip | -r start in roundtrip mode\n"
	"--throughput | -t start in throughput mode\n"
	"--version | -v print out version\n"
	"--help This usage text\n", name);
}

int get_interface_info(struct config *conf) {
	struct nl_handle *nl = nl_handle_alloc();
	unsigned char *buf = NULL;
	struct sockaddr_nl nla;
	struct nlattr *attrs[IEEE802154_ATTR_MAX+1];
	struct nlmsghdr *nlh;
	struct nl_msg *msg;
	int family;

	if (!nl)
		return 1;

	genl_connect(nl);

	/* Build and send message */
	msg = nlmsg_alloc();
	family = genl_ctrl_resolve(nl, "802.15.4 MAC");
	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_ECHO, IEEE802154_LIST_IFACE, 1);
	nla_put_string(msg, IEEE802154_ATTR_DEV_NAME, "wpan0");
	nl_send_auto_complete(nl, msg);
	nlmsg_free(msg);

	/* Receive and parse answer */
	nl_recv(nl, &nla, &buf, NULL);
	nlh = (struct nlmsghdr*)buf;
	genlmsg_parse(nlh, 0, attrs, IEEE802154_ATTR_MAX, ieee802154_policy);
	nlmsg_data(nlh);
	if (!attrs[IEEE802154_ATTR_SHORT_ADDR] || !attrs[IEEE802154_ATTR_SHORT_ADDR])
		return 1;

	/* We only handle short addresses right now */
	conf->pan_id = nla_get_u16(attrs[IEEE802154_ATTR_PAN_ID]);
	conf->src_addr = nla_get_u16(attrs[IEEE802154_ATTR_SHORT_ADDR]);

	free(buf);
	nl_close(nl);

	return 0;
}

void dump_packet(unsigned char *buf, int len) {
	int i;

	printf("Packet payload:");
	for (i = 0; i < len; i++) {
		printf(" %x", buf[i]);
	}
	printf("\n");
}

int generate_packet(unsigned char *buf, struct config *conf, int seq_num) {
	int i;

	/* Max payload size 115 byte */
	if (conf->packet_len >= MAX_PAYLOAD_LEN || conf->packet_len == 0)
		conf->packet_len = MAX_PAYLOAD_LEN;

	/* We have at least 5 byte payload for length, flags, etc*/
	if (conf->packet_len < 5)
		conf->packet_len = 5;

	buf[0] = conf->packet_len;
	buf[1] = conf->packet_type;
	buf[2] = seq_num;
	for (i = 3; i < conf->packet_len; i++) {
		buf[i] = 0xAB;
	}

	return 0;
}

int parse_flags(struct config *conf, unsigned char *buf) {

	conf->packet_type = buf[1];
	if (conf->packet_type == PACKET_CONFIG && buf[3] != 0xAB)
		conf->packets = buf[3];
	if (conf->packet_type == PACKET_CONFIG && buf[4] != 0xAB)
		conf->packet_len = buf[4];
	return 0;
}

int fire_throughput_packets(struct config *conf, int sd) {
	unsigned char *buf;
	int i;

	conf->packet_type = PACKET_THROUGHPUT;

	buf = (unsigned char *)malloc(MAX_PAYLOAD_LEN);

	for (i = 0; i < conf->packets; i++) {
		memset(buf, 0, MAX_PAYLOAD_LEN);
		generate_packet(buf, conf, i);
		send(sd, buf, conf->packet_len, 0);
		printf("Packet %i fired\n", i);
	}
	free(buf);
	return 0;
}

int measure_throughput(struct config *conf, int sd) {
	int i;
	ssize_t len, len_sum = 1;
	unsigned char *buf;
	struct timeval start_time, end_time, timeout;
	long sec, usec;
	int count;
	float throughput;

	printf("Start throughput measurement...\n");

	conf->packet_type = PACKET_CONFIG;

	buf = (unsigned char *)malloc(MAX_PAYLOAD_LEN);
	generate_packet(buf, conf, 1);
	buf[3] = conf->packets;
	buf[4] = conf->packet_len;
	//dump_packet(buf, conf->packet_len);
	send(sd, buf, conf->packet_len, 0);

	/* 2 seconds packet receive timeout */
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&timeout,sizeof(struct timeval));

	len = count = 0;
	for (i = 0; i < conf->packets; i++) {
		len = recv(sd, buf, conf->packet_len, 0);
		len_sum += len;
		printf("Packet with sequenze numer %i arrived\n", buf[2]);
		if (count > buf[2]) {
			printf("Sequenze number did not match.\n");
			//continue;
		}
		printf("Got %i, expected %i\n", buf[2], count);
		if (len > 0) {
			if (i == 0)
				gettimeofday(&start_time, NULL);
			printf("Packet %i arrived\n", count);
			count++;
		} else
			printf("Hit packet timeout\n");

		memset(buf, 0, MAX_PAYLOAD_LEN);
	}
	gettimeofday(&end_time, NULL);
	sec = end_time.tv_sec - start_time.tv_sec;
	usec = end_time.tv_usec - start_time.tv_usec;
	if (usec < 0) {
		usec += 1000000;
		sec--;
	}
	throughput = len_sum / ((float)sec + (float)usec/1000000);
	printf("Received %i bytes in %li seconds and %li usec => %f Bytes/second\n",
		(int)len_sum, sec, usec, throughput);

	free(buf);
	return 0;
}

int measure_roundtrip(struct config *conf, int sd) {
	unsigned char *buf;
	struct timeval start_time, end_time, timeout;
	long sec = 0, usec = 0;
	long sec_max = 0, usec_max = 0;
	long sec_min = 2147483647, usec_min = 2147483647;
	long sum_sec = 0, sum_usec = 0;
	int i, ret, count, seq_num;

	printf("Start roundtrip time measurement...\n");

	conf->packet_type = PACKET_ROUNDTRIP;
	buf = (unsigned char *)malloc(MAX_PAYLOAD_LEN);

	/* 2 seconds packet receive timeout */
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&timeout,sizeof(struct timeval));

	count = 0;
	for (i = 0; i < conf->packets; i++) {
		generate_packet(buf, conf, i);
		seq_num = buf[2];
		send(sd, buf, conf->packet_len, 0);
		gettimeofday(&start_time, NULL);
		ret = recv(sd, buf, conf->packet_len, 0);
		if (seq_num != buf[2]) {
			printf("Sequenze number did not match\n");
			continue;
		}
		if (ret > 0) {
			gettimeofday(&end_time, NULL);
			count++;
			sec = end_time.tv_sec - start_time.tv_sec;
			sum_sec += sec;
			usec = end_time.tv_usec - start_time.tv_usec;
			if (usec < 0) {
				usec += 1000000;
				sec--;
				sum_sec--;
			}
			sum_usec += usec;
			if (sec > sec_max)
				sec_max = sec;
			else if (sec < sec_min)
				sec_min = sec;
			if (usec > usec_max)
				usec_max = usec;
			else if (usec < usec_min)
				usec_min = usec;
			printf("Pong in %li seconds and %li usecs\n", sec, usec);
		} else
			printf("Hit packet timeout\n");
	}
	printf("Received %i from %i packets\n", count, conf->packets);
	printf("Arithmetic mean rountrip time: %f seconds and %f usecs\n",
		(float)sum_sec/(float)count, (float)sum_usec/(float)count);
	printf("Minimal time %f seconds and %f usecs\n", (float)sec_min, (float)usec_min);
	printf("Maximal time %f seconds and %f usecs\n", (float)sec_max, (float)usec_max);
	free(buf);
	return 0;
}

void init_server(struct config *conf, int sd) {
	ssize_t len;
	unsigned char *buf;
//	struct sockaddr_ieee802154 src;
//	socklen_t addrlen;

//	addrlen = sizeof(src);

	len = 0;
	printf("Server mode. Waiting for packets...\n");
	buf = (unsigned char *)malloc(MAX_PAYLOAD_LEN);

	while (1) {
		//len = recvfrom(sd, buf, MAX_PAYLOAD_LEN, 0, (struct sockaddr *)&src, &addrlen);
		len = recv(sd, buf, MAX_PAYLOAD_LEN, 0);
		printf("Received %zd bytes ", len);
		//dump_packet(buf, len);
		parse_flags(conf, buf);
		/* Roundtrip mode: send same packet back */
		if (conf->packet_type == PACKET_ROUNDTRIP) {
			printf("Entered roundtrip mode\n");
			send(sd, buf, len, 0);
		}
		if (conf->packet_type == PACKET_CONFIG) {
			printf("Entered throughput mode\n");
			fire_throughput_packets(conf, sd);
		}
	}
	free(buf);
}

int init_network(struct config *conf) {
	int sd;
	int ret;
	struct sockaddr_ieee802154 a;

	sd = socket(PF_IEEE802154, SOCK_DGRAM, 0);
	if (sd < 0) {
		perror("socket");
		return 1;
	}

	get_interface_info(conf);

	a.family = AF_IEEE802154;
	a.addr.addr_type = IEEE802154_ADDR_SHORT;
	a.addr.pan_id = conf->pan_id;

	/* Bind socket on this side */
	a.addr.short_addr = conf->src_addr;
	ret = bind(sd, (struct sockaddr *)&a, sizeof(a));
	if (ret) {
		perror("bind");
		return 1;
	}

	/* Connect to other side */
	a.addr.short_addr = conf->dst_addr;
	ret = connect(sd, (struct sockaddr *)&a, sizeof(a));
	if (ret) {
		perror("connect");
		return 1;
	}

	if (conf->server)
		init_server(conf, sd);

	if (conf->mode == MODE_ROUNDTRIP || conf->mode == MODE_BOTH)
		measure_roundtrip(conf, sd);

	if (conf->mode == MODE_THROUGHPUT || conf->mode == MODE_BOTH)
		measure_throughput(conf, sd);

	free(conf);
	shutdown(sd, SHUT_RDWR);
	close(sd);
	return 0;
}

int main(int argc, char *argv[]) {
	int c;
	struct config *conf;

	conf = (struct config *) malloc(sizeof(struct config));

	if (argc < 2) {
		usage(argv[0]);
		exit(1);
	}

	while (1) {
#ifdef HAVE_GETOPT_LONG
		int opt_idx = -1;
		c = getopt_long(argc, argv, "c:p:l:s:rtvh", perf_long_opts, &opt_idx);
#else
		c = getopt(argc, argv, "c:p:l:s:rtvh");
#endif
		if (c == -1)
			break;
		switch(c) {
		case 'c':
			conf->dst_addr = strtol(optarg, NULL, 16);
			break;
		case 's':
			conf->server = 1;
			conf->dst_addr = strtol(optarg, NULL, 16);
			break;
			break;
		case 'p':
			conf->packets = atoi(optarg);
			break;
		case 'l':
			conf->packet_len = atoi(optarg);
			break;
		case 'r':
			if (conf->mode == MODE_THROUGHPUT)
				conf->mode = MODE_BOTH;
			else
				conf->mode = MODE_ROUNDTRIP;
			break;
		case 't':
			if (conf->mode == MODE_ROUNDTRIP)
				conf->mode = MODE_BOTH;
			else
				conf->mode = MODE_THROUGHPUT;
			break;
		case 'v':
			printf(	"lowpan-perf 0.1\n");
			return 1;
		case 'h':
			usage(argv[0]);
			return 1;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	init_network(conf);
	return 0;
}
