/*
	Mac-Telnet - Connect to RouterOS or mactelnetd devices via MAC address
	Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along
	with this program; if not, write to the Free Software Foundation, Inc.,
	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#define _BSD_SOURCE
#include <libintl.h>
#include <locale.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef __LINUX__
#include <linux/if_ether.h>
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#if defined(__FreeBSD__) || defined(__APPLE__)
#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/socket.h>
#else
#include <netinet/ether.h>
#endif
#include <time.h>
#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define le32toh OSSwapLittleToHostInt32
#elif defined(__FreeBSD__)
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#include "config.h"
#include "protocol.h"
#include "extra.h"

#define _(STRING) gettext(STRING)

int init_packet(struct mt_packet *packet, enum mt_ptype ptype, unsigned char *srcmac, unsigned char *dstmac,
				unsigned short sessionkey, unsigned int counter) {
	unsigned char *data = packet->data;

	/* Packet version */
	data[0] = 1;

	/* Packet type */
	data[1] = ptype;

	/* src ethernet address */
	memcpy(data + 2, srcmac, ETH_ALEN);

	/* dst ethernet address */
	memcpy(data + 8, dstmac, ETH_ALEN);

	/* Session key */
	sessionkey = htons(sessionkey);
	memcpy(data + (mt_direction_fromserver ? 16 : 14), &sessionkey, sizeof(sessionkey));

	/* Client type: Mac Telnet */
	memcpy(data + (mt_direction_fromserver ? 14 : 16), &mt_mactelnet_clienttype, sizeof(mt_mactelnet_clienttype));

	/* Received/sent data counter */
	counter = htonl(counter);
	memcpy(data + 18, &counter, sizeof(counter));

	/* 22 bytes header */
	packet->size = 22;
	return 22;
}

int add_control_packet(struct mt_packet *packet, enum mt_cptype cptype, void *cpdata, unsigned short data_len) {
	unsigned char *data = packet->data + packet->size;
	unsigned int act_size = data_len + (cptype == MT_CPTYPE_PLAINDATA ? 0 : MT_CPHEADER_LEN);

	/* Something is really wrong. Packets should never become over 1500 bytes,
	   perform an Integer-Overflow safe check */
	if (act_size > MT_PACKET_LEN - packet->size) {
		fprintf(stderr, _("add_control_packet: ERROR, too large packet. Exceeds %d bytes\n"), MT_PACKET_LEN);
		return -1;
		// exit(1);
	}

	/* PLAINDATA isn't really a controlpacket, but we handle it here, since
	   parseControlPacket also parses raw data as PLAINDATA */
	if (cptype == MT_CPTYPE_PLAINDATA) {
		memcpy(data, cpdata, data_len);
		packet->size += data_len;
		return data_len;
	}

	/* Control Packet Magic id */
	memcpy(data, mt_mactelnet_cpmagic, sizeof(mt_mactelnet_cpmagic));

	/* Control packet type */
	data[4] = cptype;

	/* Data length */
#if BYTE_ORDER == LITTLE_ENDIAN
	{
		unsigned int templen;
		templen = htonl(data_len);
		memcpy(data + 5, &templen, sizeof(templen));
	}
#else
	memcpy(data + 5, &data_len, sizeof(data_len));
#endif

	/* Insert data */
	if (data_len > 0) {
		memcpy(data + MT_CPHEADER_LEN, cpdata, data_len);
	}

	packet->size += act_size;
	/* Control packet header length + data length */
	return act_size;
}

int init_pingpacket(struct mt_packet *packet, unsigned char *srcmac, unsigned char *dstmac) {
	init_packet(packet, MT_PTYPE_PING, srcmac, dstmac, 0, 0);

	/* Zero out sessionkey & counter */
	bzero(packet->data + 14, 4);

	/* Remove data counter field from header */
	packet->size -= 4;
	return packet->size;
}

int init_pongpacket(struct mt_packet *packet, unsigned char *srcmac, unsigned char *dstmac) {
	init_packet(packet, MT_PTYPE_PONG, srcmac, dstmac, 0, 0);

	/* Zero out sessionkey & counter */
	bzero(packet->data + 14, 4);

	/* Remove data counter field from header */
	packet->size -= 4;
	return packet->size;
}

int add_packetdata(struct mt_packet *packet, unsigned char *data, unsigned short length) {
	/* Integer-Overflow safe check */
	if (length > MT_PACKET_LEN - packet->size) {
		fprintf(stderr, _("add_control_packet: ERROR, too large packet. Exceeds %d bytes\n"), MT_PACKET_LEN);
		return -1;
	}

	memcpy(packet->data + packet->size, data, length);
	packet->size += length;

	return length;
}

void parse_packet(unsigned char *data, struct mt_mactelnet_hdr *pkthdr) {
	/* Packet version */
	pkthdr->ver = data[0];

	/* Packet type */
	pkthdr->ptype = data[1];

	/* src ethernet addr */
	memcpy(pkthdr->srcaddr, data + 2, ETH_ALEN);

	/* dst ethernet addr */
	memcpy(pkthdr->dstaddr, data + 8, ETH_ALEN);

	/* Session key */
	memcpy(&(pkthdr->seskey), data + (mt_direction_fromserver ? 14 : 16), sizeof(pkthdr->seskey));
	pkthdr->seskey = ntohs(pkthdr->seskey);

	/* server type */
	memcpy(&(pkthdr->clienttype), data + (mt_direction_fromserver ? 16 : 14), 2);

	/* Received/sent data counter */
	memcpy(&(pkthdr->counter), data + 18, sizeof(pkthdr->counter));
	pkthdr->counter = ntohl(pkthdr->counter);

	/* Set pointer to actual data */
	pkthdr->data = data + 22;
}

int parse_control_packet(unsigned char *packetdata, unsigned short data_len, struct mt_mactelnet_control_hdr *cpkthdr) {
	static unsigned char *int_data;
	static unsigned int int_data_len;
	static unsigned int int_pos;
	unsigned char *data;

	/* Store info so we can call this function once with data,
	   and then several times for each control packets. Letting this function
	   control the data position. */
	if (packetdata != NULL) {
		if (data_len == 0) {
			return 0;
		}

		int_data = packetdata;
		int_data_len = data_len;
		int_pos = 0;
	}

	/* No more data to parse? */
	if (int_pos >= int_data_len) {
		return 0;
	}

	/* Set current position in data buffer */
	data = int_data + int_pos;

	/* Check for valid minimum packet length & magic header */
	if ((int_data_len - int_pos) >= MT_CPHEADER_LEN && memcmp(data, &mt_mactelnet_cpmagic, 4) == 0) {
		/* Control packet type */
		cpkthdr->cptype = data[4];

		/* Control packet data length */
		memcpy(&(cpkthdr->length), data + 5, sizeof(cpkthdr->length));
		cpkthdr->length = ntohl(cpkthdr->length);

		/* We want no buffer overflows */
		if (cpkthdr->length > int_data_len - MT_CPHEADER_LEN - int_pos) {
			cpkthdr->length = int_data_len - MT_CPHEADER_LEN - int_pos;
		}

		/* Set pointer to actual data */
		cpkthdr->data = data + MT_CPHEADER_LEN;

		/* Remember old position, for next call */
		int_pos += cpkthdr->length + MT_CPHEADER_LEN;

		/* Read data successfully */
		return 1;

	} else {
		/* Mark data as raw terminal data */
		cpkthdr->cptype = MT_CPTYPE_PLAINDATA;
		cpkthdr->length = int_data_len - int_pos;
		cpkthdr->data = data;

		/* Consume the whole rest of the packet */
		int_pos = int_data_len;

		/* Read data successfully */
		return 1;
	}
}

int parse_mac_address(char *address, unsigned char *dstmac) {
	char *p = address;
	int colons = 0;
	int dashs = 0;

	while (*p++) {
		if (*p == ':') {
			colons++;
		} else if (*p == '-') {
			dashs++;
		}
	}

	/*
	 * Windows users often enter macs with dash instead
	 * of colon.
	 */
	if (colons == 0 && dashs == 5) {
		p = address;
		while (*p++) {
			if (*p == '-') {
				*p = ':';
			}
		}
		colons = dashs;
	}

	if (colons != 5) {
		return 0;
	} else {
		/* Convert mac address string to ether_addr struct */
#if defined(__APPLE__)
		struct ether_addr *dstmac_buf = ether_aton(address);
		if (dstmac_buf == NULL) return 0;
		memcpy(dstmac, dstmac_buf, sizeof(struct ether_addr));
#else
		if (ether_aton_r(address, (struct ether_addr *)dstmac) == NULL) {
			return 0;
		}
#endif
	}

	return 1;
}
