/*
 * Copyright (c) 2021 Jordi Cenzano
 * Created from ./echo.c
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
#include <linux/if_ether.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#define DESTMAC0 0xd0
#define DESTMAC1 0x67
#define DESTMAC2 0xe5
#define DESTMAC3 0x12
#define DESTMAC4 0x6f
#define DESTMAC5 0x8f

// NEW-IP OFFSET HEADER
struct new_ip_offset {
    __u8 shipping_offset;
    __u8 contract_offset;
    __u8 payload_offset;
};
// NEW-IP SHIPPING SEC
struct shipping_spec {
    __u8 src_addr_type;
    __u8 dst_addr_type;
    __u8 addr_cast;
    struct in_addr v4_src_addr;
    struct in_addr v4_dst_addr;
};

// LBF CONTRACT
struct latency_based_forwarding {
    __u16 contract_type;
    __u16 min_delay;
    __u16 max_delay;
    __u16 experienced_delay;
    __u16 fib_todelay;
    __u16 fib_tohops;
};

/**
 * the QUIC context
 */
static quicly_context_t ctx;
/**
 * CID seed
 */
static quicly_cid_plaintext_t next_cid;
/**
 * Verbose mode
 */
int is_verbose = 0;

static int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host, const char *port, int family, int type,
                           int proto)
{
    struct addrinfo hints, *res;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = type;
    hints.ai_protocol = proto;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((err = getaddrinfo(host, port, &hints, &res)) != 0 || res == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", host, port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL");
        return -1;
    }

    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

static void usage(const char *progname)
{
    printf("Usage: %s [options] [host]\n"
           "Options:\n"
           "  -c <file>    specifies the certificate chain file (PEM format)\n"
           "  -k <file>    specifies the private key file (PEM format)\n"
           "  -p <number>  specifies the port number (default: 4433)\n"
           "  -h           prints this help\n"
           "\n"
           "`-c` and `-k` have to be be specified\n"
           "If omitted, host defaults to 127.0.0.1.\n"
           "In this case all info received will be output to stdout, so you should have only 1 connection active\n"
           "\n"
           "Example (receives live video over QUIC):\n"
           "%s -c server.crt -k server.key -p 4433 | ffplay -i -\n",
           progname, progname);
    exit(0);
}

static void on_stop_sending(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive_reset(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    /* server: echo back to the client */
    if (quicly_sendstate_is_open(&stream->sendstate) && (input.len > 0)) {
        // Write received data to stdout
        fwrite(input.base, 1, input.len, stdout);
        fflush(stdout);

        // Show the received size to logs and send it to the client
        char str[128];
        sprintf(str, "Received: %zu bytes\n", input.len);
        if (is_verbose)
            fprintf(stderr, "%s", str);
        quicly_streambuf_egress_write(stream, str, strlen(str));
        // shutdown the stream after echoing all data
        if (quicly_recvstate_transfer_complete(&stream->recvstate))
            quicly_streambuf_egress_shutdown(stream);
    }

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);
}


void print_decoded_packet(quicly_decoded_packet_t *packet) {
    fprintf(stderr, "\n\nprinting decoded_packet\n");
    fprintf(stderr, "Packet octets length : %d\n", packet->octets.len);
    for(int i = 0; i < packet->octets.len; i++) {
        fprintf(stderr, "%x ", packet->octets.base[i]);
    }
    fprintf(stderr, "\nSource CID: %d\n", (int)packet->cid.src.len);
    
    fprintf(stderr, "Version: %x\n", packet->version);
    
    fprintf(stderr, "Encrypted offset: %zu\n", packet->encrypted_off);
    
    fprintf(stderr, "Datagram size: %zu\n", packet->datagram_size);
    if (packet->decrypted.pn != UINT64_MAX) {
        fprintf(stderr, "Packet has been decrypted; Packet number: %" PRIu64 ", Key phase: %" PRIu64 "\n",
            packet->decrypted.pn, packet->decrypted.key_phase);
    }
    
    switch (packet->_is_stateless_reset_cached) {
        case QUICLY__DECODED_PACKET_CACHED_MAYBE_STATELESS_RESET:
           fprintf(stderr, "Is stateless reset: unknown\n");
            break;
        case QUICLY__DECODED_PACKET_CACHED_IS_STATELESS_RESET:
            fprintf(stderr, "Is stateless reset: true\n");
            break;
        case QUICLY__DECODED_PACKET_CACHED_NOT_STATELESS_RESET:
            fprintf(stderr, "Is stateless reset: false\n");
            break;
    }
}

static void process_msg(quicly_conn_t **conn, struct msghdr *msg, size_t dgram_len)
{
    size_t off = 0;
    fprintf(stderr, "Payload without headers (recvfrom) , rret : %d \n", dgram_len);

    // fprintf(stderr, "dgram_len: %zu\n", dgram_len);
    for(int i = 0; i < dgram_len; i++) {
        fprintf(stderr, "%02x ", ((uint8_t *)msg->msg_iov[0].iov_base)[i]);
    }
    fprintf(stderr, "\n--------------------------------------------------------------------------------------------\n");
    /* split UDP datagram into multiple QUIC packets */
    while (off < dgram_len) {
        quicly_decoded_packet_t decoded;
        
        fprintf(stderr, "Decoding the QUIC packet ...\n");
        if (quicly_decode_packet(&ctx, &decoded, msg->msg_iov[0].iov_base, dgram_len, &off) == SIZE_MAX) {
            fprintf(stderr, "Could not decode packet\n");
            return;
        }

        // fprintf(stderr, "printing decoded packet after process msg in client\n");
            // print_decoded_packet(&decoded);
        fprintf(stderr, "quicly pakcet decoded\n");
        /* find the corresponding connection (TODO handle version negotiation, rebinding, retry, etc.) */
        if (*conn != NULL) {
            fprintf(stderr, "received new packet\n");
            
            if (quicly_is_destination(*conn, NULL, msg->msg_name, &decoded) | 1) {
                fprintf(stderr, "received packet for existing connection\n");
                quicly_receive(*conn, NULL, msg->msg_name, &decoded);
            } else {
                fprintf(stderr, "failed to accept new incoming connection only 1 connection allowed.\n");
            }
        } else {
            fprintf(stderr, "new connection , received packet\n");
                /* assume that the packet is a new connection */
                /* assume that the packet is a new connection */
                fprintf(stderr, "New connection\n");
            /* assume that the packet is a new connection */
                fprintf(stderr, "New connection\n");
            quicly_accept(conn, &ctx, NULL, msg->msg_name, &decoded, NULL, &next_cid, NULL);
        }
    }
}

// static void process_msg(quicly_conn_t **conn, struct msghdr *msg, size_t dgram_len)
// {
//     size_t off = 0;
//     size_t rret = dgram_len;
//     // decoding the raw packet
//     struct ethhdr *eth = (struct ethhdr *)(msg->msg_iov[0].iov_base);
//     // fprintf(stderr, "eth->h_proto : %x\n", eth->h_proto);
//     if (htons(eth->h_proto) == 0x88b6) {
//         fprintf(stderr, "eth->h_proto : %x\nrret : %lu\n", htons(eth->h_proto), (unsigned long int)rret);

//         // printing new_ip_offset
//         // struct new_ip_offset *new_ip_offset_val = (struct new_ip_offset *)(msg->msg_iov[0].iov_base + sizeof(struct ethhdr));
//         // fprintf(stderr, "new_ip_offset_val->shipping_offset : %x\n", new_ip_offset_val->shipping_offset);
//         // fprintf(stderr, "new_ip_offset_val->contract_offset : %x\n", new_ip_offset_val->contract_offset);
//         // fprintf(stderr, "new_ip_offset_val->payload_offset : %x\n", new_ip_offset_val->payload_offset);

//         // // print shipping_spec
//         // struct shipping_spec *shipping_spec_val =
//         //     (struct shipping_spec *)(msg->msg_iov[0].iov_base + sizeof(struct ethhdr) + sizeof(struct new_ip_offset));
//         // fprintf(stderr, "shipping_spec_val->src_addr_type : %x\n", shipping_spec_val->src_addr_type);
//         // fprintf(stderr, "shipping_spec_val->dst_addr_type : %x\n", shipping_spec_val->dst_addr_type);
//         // fprintf(stderr, "shipping_spec_val->addr_cast : %x\n", shipping_spec_val->addr_cast);
//         // // remove the ethernet header, new_ip_offset and shipping_spec from buffer
//         // //  memcpy(buf, buf + lenToPayload, rret - lenToPayload);
//         // //  rret -= lenToPayload;
//         // uint8_t tempbuf[ctx.transport_params.max_udp_payload_size];
//         // // memcpy(tempbuf, buf, sizeof(struct ethhdr));
//         // memcpy(tempbuf,
//         //        msg->msg_iov[0].iov_base + sizeof(struct ethhdr) + sizeof(struct new_ip_offset) + sizeof(struct shipping_spec),
//         //        rret - sizeof(struct ethhdr) - sizeof(struct new_ip_offset) - sizeof(struct shipping_spec));
//         // rret = rret - sizeof(struct ethhdr) - sizeof(struct new_ip_offset) - sizeof(struct shipping_spec);

//         dgram_len = rret;

//         // char ip [INET_ADDRSTRLEN] = "";
//         // char addr [200]="10.0.0.1";
//         // struct sockaddr_in  *ipv4_addr;

//         // use resolve address to get the address
//         // struct sockaddr_storage address_ipv4;
//         // socklen_t salen;
//         // char *host = "10.0.0.1";
//         // char *port = "4433";

//         // if (resolve_address((struct sockaddr *)&address_ipv4, &salen, host, port, AF_INET, SOCK_RAW, 0) != 0)
//         // exit(1);

//         // struct sockaddr_in address;
//         // address.sin_addr.s_addr = inet_addr("10.0.0.1");
//         // address.sin_port = htons(4433);

//         //Converts string to address.
//         // inet_pton (AF_INET, addr, &ipv4_addr);
//         // msg->msg_name = (struct sockaddr *)&ipv4_addr;
//         // struct sockaddr_in address;
//         // address.sin_addr.s_addr = inet_addr("10.0.0.2");
//         // address.sin_port = htons("4433");
//         // fprintf(stderr, "address_ipv4 : %s\n", (char *)&address);

//         struct sockaddr_in addr;
//         addr.sin_family = AF_INET;
//         addr.sin_port = htons(4433);
//         addr.sin_addr.s_addr = inet_addr("10.0.0.2");

//         msg->msg_name = (struct sockaddr *)&addr;

//         // msg->msg_name = (struct sockaddr *)&address;

//         fprintf("rret : %x", rret);
//         /* split UDP datagram into multiple QUIC packets */
//         while (off < dgram_len) {
//             quicly_decoded_packet_t decoded;
//             if (quicly_decode_packet(&ctx, &decoded, tempbuf, dgram_len, &off) == SIZE_MAX){
//                 fprintf(stderr, "quicly_decode_packet failed\n");
//                 return;
//             }
//                 // return;
//             /* find the corresponding connection (TODO handle version negotiation, rebinding, retry, etc.) */
//             if (*conn != NULL) {
//                 fprintf(stderr, "Exisiting connection\n");
//                 if (quicly_is_destination(*conn, NULL, msg->msg_name, &decoded) || 1) {
//                     quicly_receive(*conn, NULL, (struct sockaddr *)&addr, &decoded);
//                 } else {
//                     fprintf(stderr, "failed to accept new incoming connection, this server only allows 1 concurrent
//                     connection\n");
//                 }
//             } else {
//                 /* assume that the packet is a new connection */
//                 fprintf(stderr, "New connection\n");
//                 quicly_accept(conn, &ctx, NULL, (struct sockaddr *)&addr, &decoded, NULL, &next_cid, NULL);
//             }
//         }
//     }
// }

// static int send_one(int fd, struct sockaddr *dest, struct iovec *vec)
// {
//     struct msghdr mess = {.msg_name = dest, .msg_namelen = quicly_get_socklen(dest), .msg_iov = vec, .msg_iovlen = 1};
//     int ret;

//     while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
//         ;
//     return ret;
// }

unsigned short calculate_udp_checksum(unsigned short *buffer, int size, struct in_addr src_addr, struct in_addr dst_addr)
{
    unsigned long sum = 0;
    int i;

    // Pseudo header
    sum += (src_addr.s_addr >> 16) & 0xFFFF;
    sum += src_addr.s_addr & 0xFFFF;
    sum += (dst_addr.s_addr >> 16) & 0xFFFF;
    sum += dst_addr.s_addr & 0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += htons(size);

    // UDP header and data
    for (i = 0; i < size / 2; i++) {
        sum += buffer[i];
    }

    if (size % 2) {
        sum += ((unsigned short)buffer[i]) & 0xFF00;
    }

    // Fold the sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (unsigned short)(~sum);
}

static int send_one(int fd, struct sockaddr *dest, struct iovec *vec)
{
    // fprintf(stderr, "\nsend_one in server\n");
    // fprintf(stderr, "vec , payload before sending in server side : \n");
    // fprintf(stderr, "vec->iov_len : %d\n", vec->iov_len);
    fprintf(stderr, "Sending Packet from server\n");
    fprintf(stderr, "Payload before adding newip headers\trret : %d\n", vec->iov_len);
    // for (int i = 0; i < rret; i++)
    //     fprintf(stderr, "%02x ", buf[i]);
                // fprintf(stderr, "=======\n");
    for(int jj = 0;jj<vec->iov_len;jj ++){
    //     // print contents of vec 
        fprintf(stderr, "%02x ", ((uint8_t *)vec->iov_base)[jj]);   
    }

    fprintf(stderr, "\n------------------------------------------------------------------------------------------------\n");
    
    // Calculate the total length of the packet, including the custom headers
    int total_len =
        sizeof(struct ethhdr) + sizeof(struct new_ip_offset) + sizeof(struct shipping_spec) + sizeof(struct udphdr) + vec->iov_len;
    struct ifreq ifreq_i;
    memset(&ifreq_i, 0, sizeof(ifreq_i));
    strncpy(ifreq_i.ifr_name, "h2_h1", IFNAMSIZ - 1);
    if ((ioctl(fd, SIOCGIFINDEX, &ifreq_i)) < 0) // getting the the Interface index
        printf("error in index ioctl reading 1");
    struct ifreq ifreq_c;
    memset(&ifreq_c, 0, sizeof(ifreq_c));
    strncpy(ifreq_c.ifr_name, "h2_h1", IFNAMSIZ - 1);
    if ((ioctl(fd, SIOCGIFHWADDR, &ifreq_c)) < 0) // getting MAC Address
        printf("error in SIOCGIFHWADDR ioctl reading 2");

    // Allocate a buffer to hold the packet data
    char *sendbuff = (unsigned char *)malloc(total_len);
    memset(sendbuff, 0, total_len);

    // Create the custom headers and write them to the buffer
    struct ethhdr *eth = (struct ethhdr *)(sendbuff);
    eth->h_source[0] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]);
    eth->h_source[1] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]);
    eth->h_source[2] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]);
    eth->h_source[3] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]);
    eth->h_source[4] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]);
    eth->h_source[5] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]);
    eth->h_dest[0] = DESTMAC0;
    eth->h_dest[1] = DESTMAC1;
    eth->h_dest[2] = DESTMAC2;
    eth->h_dest[3] = DESTMAC3;
    eth->h_dest[4] = DESTMAC4;
    eth->h_dest[5] = DESTMAC5;
    eth->h_proto = htons(0x88b6);
    struct new_ip_offset *new_ip_offset_val;
    new_ip_offset_val = (struct new_ip_offset *)(sendbuff + sizeof(struct ethhdr));
    new_ip_offset_val->shipping_offset = 1;
    new_ip_offset_val->contract_offset = 2;
    new_ip_offset_val->payload_offset = 3;

    struct shipping_spec *shipping_spec_val;
    shipping_spec_val = (struct shipping_spec *)(sendbuff + sizeof(struct ethhdr) + sizeof(struct new_ip_offset));
    shipping_spec_val->src_addr_type = 1;
    shipping_spec_val->dst_addr_type = 2;
    shipping_spec_val->addr_cast = 3;

    // ipv4 address
    struct in_addr src_addr;
    inet_pton(AF_INET, "10.0.0.1", &src_addr);

    struct in_addr dst_addr;
    inet_pton(AF_INET, "10.0.0.2", &dst_addr);

    shipping_spec_val->v4_dst_addr = dst_addr;
    shipping_spec_val->v4_src_addr = src_addr;


    struct udphdr *udp_header =
        (struct udphdr *)(sendbuff + sizeof(struct ethhdr) + sizeof(struct new_ip_offset) + sizeof(struct shipping_spec));

    udp_header->source = htons(4433);
    udp_header->dest = htons(50001);
    udp_header->len = htons(vec->iov_len + sizeof(struct udphdr));
    // udp_header->check = 0;
    udp_header->check = calculate_udp_checksum((unsigned short *)(sendbuff + sizeof(struct ethhdr) + sizeof(struct new_ip_offset) + sizeof(struct shipping_spec)), vec->iov_len + sizeof(struct udphdr), src_addr, dst_addr);

    char *temp = (char *)(sendbuff + sizeof(struct ethhdr) + sizeof(struct new_ip_offset) + sizeof(struct shipping_spec) +
                          sizeof(struct udphdr));
    char **pChar;
    pChar = &temp;
    memcpy(*pChar, vec->iov_base, vec->iov_len);

    struct iovec iov[1];
    iov[0].iov_base = sendbuff;
    iov[0].iov_len = total_len;
    struct sockaddr_ll sadr_ll;
    sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex;
    sadr_ll.sll_halen = ETH_ALEN;
    sadr_ll.sll_addr[0] = DESTMAC0;
    sadr_ll.sll_addr[1] = DESTMAC1;
    sadr_ll.sll_addr[2] = DESTMAC2;
    sadr_ll.sll_addr[3] = DESTMAC3;
    sadr_ll.sll_addr[4] = DESTMAC4;
    sadr_ll.sll_addr[5] = DESTMAC5;
    sadr_ll.sll_family = AF_PACKET;

    struct msghdr mess = {.msg_name = dest, .msg_namelen = sizeof(sadr_ll), .msg_iov = vec, .msg_iovlen = 1};
    mess.msg_name = &sadr_ll;
    mess.msg_namelen = sizeof(sadr_ll);
    mess.msg_iov = iov;
    mess.msg_iovlen = 1;
    mess.msg_control = 0;
    mess.msg_controllen = 0;
    mess.msg_flags = 0;
    int ret;

    while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;
    return ret;
}

static int run_loop_server(int fd)
{
    quicly_conn_t *conn = NULL; /* this server only accepts a single connection */

    while (1) {

        /* wait for sockets to become readable, or some event in the QUIC stack to fire */
        fd_set readfds;
        struct timeval tv;
        do {
            int64_t first_timeout = INT64_MAX, now = ctx.now->cb(ctx.now);
            if (conn != NULL) {
                int64_t conn_timeout = quicly_get_first_timeout(conn);
                if (conn_timeout < first_timeout)
                    first_timeout = conn_timeout;
            }
            if (now < first_timeout) {
                int64_t delta = first_timeout - now;
                if (delta > 1000 * 1000)
                    delta = 1000 * 1000;
                tv.tv_sec = delta / 1000;
                tv.tv_usec = (delta % 1000) * 1000;
            } else {
                tv.tv_sec = 1000;
                tv.tv_usec = 0;
            }
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);
        } while (select(fd + 1, &readfds, NULL, NULL, &tv) == -1 && errno == EINTR);

        /* read the QUIC fd */
        if (FD_ISSET(fd, &readfds)) {
            uint8_t buf[4096];
            // struct sockaddr_storage sa;
            // struct sockaddr_ll sa;

            struct sockaddr_ll sa;
            memset(&sa, 0, sizeof(sa));
            sa.sll_family = AF_PACKET;
            sa.sll_ifindex = if_nametoindex("h2_h1");
            sa.sll_protocol = htons(0x88b6);
            struct sockaddr_in hi;

            struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
            struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};
            ssize_t rret;
            while ((rret = recvmsg(fd, &msg, 0)) == -1 && errno == EINTR)
                ;
            fprintf(stderr, "\nReceived %ld bytes in server (recvmsg)\n", rret);
            // fprintf(stderr, "Received msg_iovlen %d\n", msg.msg_iovlen);

            if (rret > 0) {
                // fprintf(stderr, "msg->msg_name = %hu", (*(struct sockaddr_ll *)msg.msg_iov).sll_family);

                // // print contents of vec using for loop
                // fprintf(stderr, "\nbefore removing headers , \n rret : %d \nvec contents: \n", rret);
                // for (int i = 0; i < rret; i++)
                //     fprintf(stderr, "%02x ", buf[i]);
                // fprintf(stderr, "=======\n");

                // changing msg->msg_name

                struct ethhdr *eth = (struct ethhdr *)(msg.msg_iov[0].iov_base);

                struct new_ip_offset *new_ip_offset_val = (struct new_ip_offset *)(msg.msg_iov[0].iov_base + sizeof(struct ethhdr));
                // fprintf(stderr, "new_ip_offset_val->shipping_offset : %x\n", new_ip_offset_val->shipping_offset);
                // fprintf(stderr, "new_ip_offset_val->contract_offset : %x\n", new_ip_offset_val->contract_offset);
                // fprintf(stderr, "new_ip_offset_val->payload_offset : %x\n", new_ip_offset_val->payload_offset);

                // print shipping_spec
                struct shipping_spec *shipping_spec_val =
                    (struct shipping_spec *)(msg.msg_iov[0].iov_base + sizeof(struct ethhdr) + sizeof(struct new_ip_offset));
                // fprintf(stderr, "shipping_spec_val->src_addr_type : %x\n", shipping_spec_val->src_addr_type);
                // fprintf(stderr, "shipping_spec_val->dst_addr_type : %x\n", shipping_spec_val->dst_addr_type);
                // fprintf(stderr, "shipping_spec_val->addr_cast : %x\n", shipping_spec_val->addr_cast);

                struct in_addr src_addr;
                struct in_addr dst_addr;

                src_addr = shipping_spec_val->v4_src_addr;
                dst_addr = shipping_spec_val->v4_dst_addr;

                struct udphdr *udp = (struct udphdr *)(msg.msg_iov[0].iov_base + sizeof(struct ethhdr) +
                                                       sizeof(struct new_ip_offset) + sizeof(struct shipping_spec));

                // uint8_t tempbuf[ctx.transport_params.max_udp_payload_size];
                // // memcpy(tempbuf, buf, sizeof(struct ethhdr));
                // memcpy(tempbuf,
                //     msg.msg_iov[0].iov_base + sizeof(struct ethhdr) + sizeof(struct new_ip_offset) + sizeof(struct shipping_spec)
                //     + sizeof(struct udphdr), rret - sizeof(struct ethhdr) - sizeof(struct new_ip_offset) - sizeof(struct
                //     shipping_spec) - sizeof(struct udphdr));
                // rret = rret - sizeof(struct ethhdr) - sizeof(struct new_ip_offset) - sizeof(struct shipping_spec)  -
                // sizeof(struct udphdr);

                // msg.msg_iov[0].iov_base = tempbuf;
                // msg.msg_iov[0].iov_len = rret;

                // use memmove to move the data in the buffer , remove the ethernet header, ip header, udp header
                memmove(msg.msg_iov[0].iov_base,
                        msg.msg_iov[0].iov_base + sizeof(struct ethhdr) + sizeof(struct new_ip_offset) +
                            sizeof(struct shipping_spec) + sizeof(struct udphdr),
                        rret - sizeof(struct ethhdr) - sizeof(struct new_ip_offset) - sizeof(struct shipping_spec) -
                            sizeof(struct udphdr));

                rret = rret - sizeof(struct ethhdr) - sizeof(struct new_ip_offset) - sizeof(struct shipping_spec) -
                       sizeof(struct udphdr);

                // rret = sizeof(msg.msg_iov[0].iov_base);
                struct sockaddr_in new_sock_addr_in;
                new_sock_addr_in.sin_family = AF_INET;
                new_sock_addr_in.sin_port = udp->source;
                new_sock_addr_in.sin_addr = src_addr;

                msg.msg_name = &new_sock_addr_in;
                msg.msg_namelen = sizeof(new_sock_addr_in);

                // printing contents of iov base

                // fprintf(stderr, "\nvec contents after removing headers , rret : %d \n", rret);
                // for (int i = 0; i < rret; i++)
                //     fprintf(stderr, "%02x ", *(uint8_t *)(msg.msg_iov[0].iov_base + i));
                // fprintf(stderr, "\n*****************************************\n");
                fprintf(stderr, "\nProcessing data in server process_msg() ...\n");                
                process_msg(&conn, &msg, rret);
            }
        }

        /* send QUIC packets, if any */
        if (conn != NULL) {
            quicly_address_t dest, src;
            /*
            typedef union st_quicly_address_t {
            struct sockaddr sa;
            struct sockaddr_in sin;
            struct sockaddr_in6 sin6;
            } quicly_address_t;
            */
            struct iovec dgrams[10];
            uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * ctx.transport_params.max_udp_payload_size];
            size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);
            int ret = quicly_send(conn, &dest, &src, dgrams, &num_dgrams, dgrams_buf, sizeof(dgrams_buf));
            
            switch (ret) {
            case 0: {
                size_t j;
                for (j = 0; j != num_dgrams; ++j) {
                    send_one(fd, &dest.sa, &dgrams[j]);
                }
            } break;
            case QUICLY_ERROR_FREE_CONNECTION:
                /* connection has been closed, free */
                quicly_free(conn);
                conn = NULL;
                break;
            default:
                // fprintf(stderr, "quicly_send returned %d\n", ret);
                return 1;
            }
        }
    }

    return 0;
}

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit, on_stop_sending, on_receive,
        on_receive_reset};
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
        return ret;
    stream->callbacks = &stream_callbacks;
    return 0;
}

int main(int argc, char **argv)
{
    ptls_openssl_sign_certificate_t sign_certificate;
    ptls_context_t tlsctx = {
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
    };
    quicly_stream_open_t stream_open = {on_stream_open};
    char *host = "10.0.0.1", *port = "4433";
    struct sockaddr_storage sas;
    //

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = if_nametoindex("h2_h1");
    sa.sll_protocol = htons(0x88b6);

    socklen_t salen;
    int ch, fd;

    /* setup quic context */
    ctx = quicly_spec_context;
    ctx.tls = &tlsctx;
    quicly_amend_ptls_context(ctx.tls);
    ctx.stream_open = &stream_open;

    /* resolve command line options and arguments */
    while ((ch = getopt(argc, argv, "c:k:p:h:v")) != -1) {
        switch (ch) {
        case 'c': /* load certificate chain */ {
            int ret;
            if ((ret = ptls_load_certificates(&tlsctx, optarg)) != 0) {
                fprintf(stderr, "failed to load certificates from file %s:%d\n", optarg, ret);
                exit(1);
            }
        } break;
        case 'k': /* load private key */ {
            FILE *fp;
            if ((fp = fopen(optarg, "r")) == NULL) {
                fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
                exit(1);
            }
            EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
            fclose(fp);
            if (pkey == NULL) {
                fprintf(stderr, "failed to load private key from file:%s\n", optarg);
                exit(1);
            }
            ptls_openssl_init_sign_certificate(&sign_certificate, pkey);
            EVP_PKEY_free(pkey);
            tlsctx.sign_certificate = &sign_certificate.super;
        } break;
        case 'p': /* port */
            port = optarg;
            break;
        case 'v': /* verbose */
            is_verbose = 1;
            break;
        case 'h': /* help */
            usage(argv[0]);
            break;
        default:
            exit(1);
            break;
        }
    }
    if ((tlsctx.certificates.count <= 0) || (tlsctx.sign_certificate == NULL)) {
        fprintf(stderr, "-c and -k options must be used\n");
        exit(1);
    }
    argc -= optind;
    argv += optind;
    if (argc != 0)
        host = *argv++;
    if (resolve_address((struct sockaddr *)&sas, &salen, host, port, AF_INET, SOCK_DGRAM, 0) != 0)
        exit(1);

    // from client
    /* open socket on any port (as a client) */
    // if ((fd = socket(sa.ss_family, SOCK_DGRAM, 0)) == -1) {
    //     perror("socket(2) failed");
    //     exit(1);
    // }
    ///
    if ((fd = socket(AF_PACKET, SOCK_RAW, htons(0x88b6))) == -1) {
        perror("socket(2) failed for AF_PACKET");
        exit(1);
    }
    ///
    // end from client

    // /* open socket, on the specified port (as a server) */
    // if ((fd = socket(sa.ss_family, SOCK_DGRAM, 0)) == -1) {
    //     perror("socket(2) failed");
    //     exit(1);
    // }
    // fcntl(fd, F_SETFL, O_NONBLOCK);
    int reuseaddr = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("h2_h1");
    sll.sll_protocol = htons(0x88b6);
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        perror("bind(2) failed for AF_PACKET");
        exit(1);
    }

    // if (bind(fd, (struct sockaddr *)&sa, salen) != 0) {
    // perror("bind(2) failed 533");
    // exit(1);
    // }

    /* enter the event loop with a connection object */
    return run_loop_server(fd);
}
