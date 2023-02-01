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

#include <linux/if_ether.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <getopt.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
// #include <picotls.h>
#if QUICLY_HAVE_FUSION
#include "picotls/fusion.h"
#endif
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
// #include "../deps/picotls/t/util.h"
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

#define DESTMAC0 0x00
#define DESTMAC1 0x00
#define DESTMAC2 0x00
#define DESTMAC3 0x00
#define DESTMAC4 0x00
#define DESTMAC5 0x00

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
           "  -v Show messages from server"
           "  -p <number>  specifies the port number (default: 4433)\n"
           "  -h           prints this help\n"
           "\n"
           "If omitted, host defaults to 127.0.0.1.\n"
           "\n"
           "Example (sends live video over QUIC):\n"
           "ffmpeg -i \"udp://localhost:5000\" -c copy -f mpegts - | %s -p 4433 localhost\n",
           progname, progname);
    exit(0);
}

static int forward_stdin(quicly_conn_t *conn)
{
    quicly_stream_t *stream0;
    const size_t READ_BLOCK_SIZE = 188 * 6; // Assumed input is transport stream
    char buf[READ_BLOCK_SIZE];
    size_t rret;

    if ((stream0 = quicly_get_stream(conn, 0)) == NULL || !quicly_sendstate_is_open(&stream0->sendstate))
        return 0;

    /* Read binary from stdin */
    while ((rret = read(STDIN_FILENO, buf, READ_BLOCK_SIZE)) == -1 && errno == EINTR)
        ;

    fprintf(stderr, "Read from stdin: %zu bytes\n", rret);
    
    // Something wrong!
    if (rret < 0) {
        // Show error and close the stream
        fprintf(stderr, "failed to read from stdin");
        rret = 0;
    }

    if (rret == 0) {
        fprintf(stderr, "Closing\n");
        /* stdin closed, close the send-side of stream0 */
        quicly_streambuf_egress_shutdown(stream0);
        return 0;
    } else {
        /* write data to send buffer */
        quicly_streambuf_egress_write(stream0, buf, rret);
        return 1;
    }
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

    /* print to stdout any data re receive from server*/
    if (is_verbose) {
        fwrite(input.base, 1, input.len, stdout);
        fflush(stdout);
    }
    /* initiate connection close after receiving all data */
    if (quicly_recvstate_transfer_complete(&stream->recvstate))
        quicly_close(stream->conn, 0, "");

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);
}

// static void process_msg(quicly_conn_t *client, struct msghdr *msg, size_t dgram_len)
// {
//     size_t off = 0;


//     /* parse Ethernet and IP headers to extract data payload */
//     struct ethhdr *eth = (struct ethhdr *)(msg->msg_iov[0].iov_base);
//     struct iphdr *ip = (struct iphdr *)(msg->msg_iov[0].iov_base + sizeof(struct ethhdr));
//     printf("Received packet in pipeclient , length: %d bytes", dgram_len);
//     uint8_t *payload = msg->msg_iov[0].iov_base + sizeof(struct ethhdr) + sizeof(struct iphdr);
//     size_t payload_len = msg->msg_iov[0].iov_len - sizeof(struct ethhdr) - sizeof(struct iphdr);

//     /* split UDP datagram into multiple QUIC packets */
//     while (off < dgram_len) {
//         quicly_decoded_packet_t decoded;
//         if (quicly_decode_packet(&ctx, &decoded, payload, payload_len, &off) == SIZE_MAX)
//             return;

//         if (client != NULL) {
//             if (quicly_is_destination(client, NULL, msg->msg_name, &decoded))
//                 quicly_receive(client, NULL, msg->msg_name, &decoded);
//         }

//         /* receive QUIC packet */
//         if (client != NULL) {
//             if (quicly_is_destination(client, NULL, (struct sockaddr *)&sa, &decoded))
//                 quicly_receive(client, NULL, (struct sockaddr *)&sa, &decoded);
//         }
//     }
// }

// new ip process_
static void process_msg(quicly_conn_t **conn, struct msghdr *msg, size_t dgram_len)
{
    size_t off = 0;
    size_t rret = dgram_len;
    //decoding the raw packet
    struct ethhdr *eth = (struct ethhdr *)(msg->msg_iov[0].iov_base);
    if (htons(eth->h_proto) == 0x88b6){      
    fprintf(stderr, "eth->h_proto : %x\nrret : %lu\n", htons(eth->h_proto), (unsigned long int)rret);        
    
    //printing new_ip_offset
    struct new_ip_offset *new_ip_offset_val = (struct new_ip_offset *)(msg->msg_iov[0].iov_base + sizeof(struct ethhdr));
    fprintf(stderr, "new_ip_offset_val->shipping_offset : %x\n", new_ip_offset_val->shipping_offset);
    fprintf(stderr, "new_ip_offset_val->contract_offset : %x\n", new_ip_offset_val->contract_offset);
    fprintf(stderr, "new_ip_offset_val->payload_offset : %x\n", new_ip_offset_val->payload_offset);
    
    // print shipping_spec
    struct shipping_spec *shipping_spec_val = (struct shipping_spec *)(msg->msg_iov[0].iov_base + sizeof(struct ethhdr) + sizeof(struct new_ip_offset));
    fprintf(stderr, "shipping_spec_val->src_addr_type : %x\n", shipping_spec_val->src_addr_type);
    fprintf(stderr, "shipping_spec_val->dst_addr_type : %x\n", shipping_spec_val->dst_addr_type);
    fprintf(stderr, "shipping_spec_val->addr_cast : %x\n", shipping_spec_val->addr_cast);
    //remove the ethernet header, new_ip_offset and shipping_spec from buffer
    // memcpy(buf, buf + lenToPayload, rret - lenToPayload);
    // rret -= lenToPayload;
    uint8_t tempbuf[ctx.transport_params.max_udp_payload_size];
    // memcpy(tempbuf, buf, sizeof(struct ethhdr));
    memcpy(tempbuf, msg->msg_iov[0].iov_base + sizeof(struct ethhdr) + sizeof(struct new_ip_offset) + sizeof(struct shipping_spec), rret - sizeof(struct ethhdr) - sizeof(struct new_ip_offset) - sizeof(struct shipping_spec));
    rret = rret - sizeof(struct ethhdr) -  sizeof(struct new_ip_offset) - sizeof(struct shipping_spec);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    addr.sin_addr.s_addr = inet_addr("10.0.0.1");

    msg->msg_name = (struct sockaddr *)&addr;
    dgram_len = rret;

    /* split UDP datagram into multiple QUIC packets */
    while (off < dgram_len) {
        quicly_decoded_packet_t decoded;
        if (quicly_decode_packet(&ctx, &decoded, tempbuf, dgram_len, &off) == SIZE_MAX)
            return;
        /* find the corresponding connection (TODO handle version negotiation, rebinding, retry, etc.) */
        if (*conn != NULL) {
            if (quicly_is_destination(*conn, NULL, msg->msg_name, &decoded) || 1) {
                quicly_receive(*conn, NULL, (struct sockaddr *)&addr, &decoded);
            } else {
                fprintf(stderr, "\nfailed to accept new incoming connection, this server only allows 1 concurrent connection\n");
            }
        } else {
            /* assume that the packet is a new connection */
            quicly_accept(conn, &ctx, NULL, (struct sockaddr *)&addr, &decoded, NULL, &next_cid, NULL);
        }
    }
    }
}
/*
ipv4
static void process_msg(quicly_conn_t *client, struct msghdr *msg, size_t dgram_len)
{   

    size_t off = 0;
    // Parse ethhdr 
    struct ethhdr *eth = (struct ethhdr *)(msg->msg_iov[0].iov_base);
    if (eth->h_proto == htons(ETH_P_IP))
        {       
            // Parse ippdr
            struct iphdr *ip = (struct iphdr *)(msg->msg_iov[0].iov_base + sizeof(struct ethhdr));

            // remove the ethernet header and IP header from the payload 
            uint8_t *payload = msg->msg_iov[0].iov_base + sizeof(struct ethhdr) + sizeof(struct iphdr);
            size_t payload_len = dgram_len - sizeof(struct ethhdr) - sizeof(struct iphdr);


            // set the payload in a new iovec structure to pass to quicly_decode_packet 
            // struct iovec vec = {.iov_base = payload, .iov_len = payload_len};
            size_t off = 0;

            while (off < dgram_len)
            {
                quicly_decoded_packet_t decoded;
                if (quicly_decode_packet(&ctx, &decoded, payload , payload_len , &off) == SIZE_MAX)
                    return;

                if (client != NULL) {
                    if (quicly_is_destination(client, NULL, msg->msg_name, &decoded))
                    quicly_receive(client, NULL, msg->msg_name, &decoded);
                 }
        }
    }
}
*/
// static int send_one(int fd, struct sockaddr *dest, struct iovec *vec)
// {

//     ///-------
//     // Get interface index and source MAC address
//     struct ifreq ifreq_i;
//     memset(&ifreq_i, 0, sizeof(ifreq_i));
//     strncpy(ifreq_i.ifr_name, "h1_h2", IFNAMSIZ - 1);
//     if ((ioctl(fd, SIOCGIFINDEX, &ifreq_i)) < 0) {  // getting the the Interface index
//         perror("error in index ioctl reading");
//         return -1;
//     }

//     struct ifreq ifreq_c;
//     memset(&ifreq_c, 0, sizeof(ifreq_c));
//     strncpy(ifreq_c.ifr_name, "h1_h2", IFNAMSIZ - 1);
//     if ((ioctl(fd, SIOCGIFHWADDR, &ifreq_c)) < 0) {  // getting MAC Address
//         perror("error in SIOCGIFHWADDR ioctl reading");
//         return -1;
//     }
//     ///-------
//     // struct msghdr mess = {.msg_name = dest, .msg_namelen = quicly_get_socklen(dest), .msg_iov = vec, .msg_iovlen = 1};

//     struct msghdr mess = {
//     .msg_name = (struct sockaddr_ll *) dest,
//     .msg_namelen = sizeof(struct sockaddr_ll),
//     .msg_iov = vec,
//     .msg_iovlen = 1
//     };

//     int ret;  
//     while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
//         ;
//     return ret;
// }

// newip changes_

static int send_one(int fd, struct sockaddr *dest, struct iovec *vec)
{   

    // Calculate the total length of the packet, including the custom headers
    int total_len = sizeof(struct ethhdr) + sizeof(struct new_ip_offset) + sizeof(struct shipping_spec) + vec->iov_len;
    struct ifreq ifreq_i;
    memset(&ifreq_i, 0, sizeof(ifreq_i));
    strncpy(ifreq_i.ifr_name, "h1_h2", IFNAMSIZ - 1);
    if ((ioctl(fd, SIOCGIFINDEX, &ifreq_i)) < 0) // getting the the Interface index
        printf("error in index ioctl reading 1");
    struct ifreq ifreq_c;
    memset(&ifreq_c, 0, sizeof(ifreq_c));
    strncpy(ifreq_c.ifr_name, "h1_h2", IFNAMSIZ - 1);
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
        
        char *temp = (char *)(sendbuff + sizeof(struct ethhdr) + sizeof(struct new_ip_offset) + sizeof(struct shipping_spec));
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
    int ret;

    while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;
    return ret;
}

// ip
// static int send_one(int fd, struct sockaddr *dest, struct iovec *vec)
// {
//     // Get interface index and source MAC address
//     struct ifreq ifreq_i;
//     memset(&ifreq_i, 0, sizeof(ifreq_i));
//     strncpy(ifreq_i.ifr_name, "h1_h2", IFNAMSIZ - 1);
//     if ((ioctl(fd, SIOCGIFINDEX, &ifreq_i)) < 0) {  // getting the the Interface index
//         perror("error in index ioctl reading");
//         return -1;
//     }

//     struct ifreq ifreq_c;
//     memset(&ifreq_c, 0, sizeof(ifreq_c));
//     strncpy(ifreq_c.ifr_name, "h1_h2", IFNAMSIZ - 1);
//     if ((ioctl(fd, SIOCGIFHWADDR, &ifreq_c)) < 0) {  // getting MAC Address
//         perror("error in SIOCGIFHWADDR ioctl reading");
//         return -1;
//     }

//     // Set up the Ethernet header
//     struct ethhdr eth_hdr;
//     memset(&eth_hdr, 0, sizeof(eth_hdr));
//     eth_hdr.h_proto = htons(ETH_P_IP); 
//     eth_hdr.h_source[0] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]);
//     eth_hdr.h_source[1] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]);
//     eth_hdr.h_source[2] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]);
//     eth_hdr.h_source[3] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]);
//     eth_hdr.h_source[4] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]);
//     eth_hdr.h_source[5] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]);
//     memcpy(eth_hdr.h_dest, "\x00\x00\x00\x00\x00\x00", ETH_ALEN);  // destination MAC address fill with zeros for now

//     // Set up the IP header
//     struct iphdr ip_hdr;
//     memset(&ip_hdr, 0, sizeof(ip_hdr));
//     ip_hdr.version = 4; 
//     ip_hdr.ihl = sizeof(ip_hdr) / 4; 
//     ip_hdr.ttl = 64;  
//     ip_hdr.protocol = IPPROTO_UDP;  // transport protocol
//     ip_hdr.saddr = ((struct sockaddr_in *)&ifreq_i.ifr_addr)->sin_addr.s_addr;  // source IP address
//     ip_hdr.daddr = ((struct sockaddr_in *)dest)->sin_addr.s_addr;  // destination IP address


//     size_t total_len = sizeof(eth_hdr) + sizeof(ip_hdr) + vec->iov_len;

//     // Allocate memory for the packet
//     char *sendbuff = (unsigned char *)malloc(total_len);
//     memset(sendbuff, 0, total_len);

//     // Copy the Ethernet header and IP header into the packet
//     memcpy(sendbuff, &eth_hdr, sizeof(eth_hdr));
//     memcpy(sendbuff + sizeof(eth_hdr), &ip_hdr, sizeof(ip_hdr));

//     // Copy the payload (data) into the packet
//     memcpy(sendbuff + sizeof(eth_hdr) + sizeof(ip_hdr), vec->iov_base, vec->iov_len);

//     struct iovec iov[1];
//     iov[0].iov_base = sendbuff;
//     iov[0].iov_len = total_len;

//     struct msghdr msg;
//     memset(&msg, 0, sizeof(msg));
//     msg.msg_name = dest;
//     msg.msg_namelen = sizeof(*dest);
//     msg.msg_iov = iov;
//     msg.msg_iovlen = 1;

//     struct sockaddr_ll sll;
//     memset(&sll, 0, sizeof(sll));
//     sll.sll_ifindex = ifreq_i.ifr_ifindex;  
//     sll.sll_family = AF_PACKET;             
//     sll.sll_protocol = htons(ETH_P_IP);    

//     msg.msg_name = (void *)&sll;
//     msg.msg_namelen = sizeof(sll);

//     int ret;
//     while ((ret = sendmsg(fd, &msg, 0)) == -1 && errno == EINTR);
//     free(sendbuff);
//     return ret;
// }

static int run_loop_client(int fd, quicly_conn_t *client)
{
    int read_stdin = 1;

    while (1) {      
        /* wait for sockets to become readable, or some event in the QUIC stack to fire */
        fd_set readfds;
        struct timeval tv;
        do {
            int64_t first_timeout = INT64_MAX, now = ctx.now->cb(ctx.now);
            int64_t conn_timeout = quicly_get_first_timeout(client);
            if (conn_timeout < first_timeout)
                first_timeout = conn_timeout;
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
            if (read_stdin)
                FD_SET(STDIN_FILENO, &readfds);
        } while (select(fd + 1, &readfds, NULL, NULL, &tv) == -1 && errno == EINTR);

        /* read the QUIC fd */
        if (FD_ISSET(fd, &readfds)) {
            uint8_t buf[4096];
            struct sockaddr_storage sas;


            struct sockaddr_ll sa;
            memset(&sa, 0, sizeof(sa));
            sa.sll_family = AF_PACKET;
            sa.sll_ifindex = if_nametoindex("h1_h2");
            sa.sll_protocol = htons(0x88b6);


            struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
            struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};
            ssize_t rret;
            while ((rret = recvmsg(fd, &msg, 0)) == -1 && errno == EINTR)
                ;
            fprintf(stderr, "recvmsg returned %zd in client\n", rret);
            if (rret > 0){
                
           
                process_msg(client, &msg, rret); }
        }
    
        if (FD_ISSET(0, &readfds)) {
            assert(client != NULL);
            if (!forward_stdin(client))
                read_stdin = 0;
        }

        /* send QUIC packets, if any */
        quicly_address_t dest, src;
        // dest.sa.sa_family = AF_PACKET;
        // src.sa.sa_family = AF_PACKET;


        struct iovec dgrams[10];
        uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * ctx.transport_params.max_udp_payload_size];
        size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);
        int ret = quicly_send(client, &dest, &src, dgrams, &num_dgrams, dgrams_buf, sizeof(dgrams_buf));
        switch (ret) {
        case 0: {
            size_t j;
            for (j = 0; j != num_dgrams; ++j) {
                send_one(fd, &dest.sa, &dgrams[j]);
            }
        } break;
        case QUICLY_ERROR_FREE_CONNECTION:
            /* connection has been closed, free, and exit when running as a client */
            quicly_free(client);
            return 0;
        default:
            fprintf(stderr, "quicly_send returned %d\n", ret);
            return 1;
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
    ptls_context_t tlsctx = {
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
    };
    quicly_stream_open_t stream_open = {on_stream_open};
    char *host = "10.0.0.2", *port = "4433";
    struct sockaddr_storage sas;

    struct sockaddr_ll sa;
            memset(&sa, 0, sizeof(sa));
            sa.sll_family = AF_PACKET;
            sa.sll_ifindex = if_nametoindex("h1_h2");
            sa.sll_protocol = htons(0x88b6);


    socklen_t salen;
    int ch, fd;

    /* setup quic context */
    ctx = quicly_spec_context;
    ctx.tls = &tlsctx;
    quicly_amend_ptls_context(ctx.tls);
    ctx.stream_open = &stream_open;

    /* resolve command line options and arguments */
    while ((ch = getopt(argc, argv, "p:h:v")) != -1) {
        switch (ch) {
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
    argc -= optind;
    argv += optind;
    if (argc != 0)
        host = *argv++;
    if (resolve_address((struct sockaddr *)&sas, &salen, host, port, AF_INET, SOCK_DGRAM, 0) != 0)
        exit(1);

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


    ///
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex("h1_h2");
        sll.sll_protocol = htons(0x88b6);
        if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
            perror("bind(2) failed for AF_PACKET");
            exit(1);
        }
    ///
    // fcntl(fd, F_SETFL, O_NONBLOCK);
    // struct sockaddr_in local;
    // memset(&local, 0, sizeof(local));
    // if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
    //     perror("bind(2) failed");
    //     exit(1);
    // }

    quicly_conn_t *client = NULL;
    /* initiate a connection, and open a stream */
    int ret;
    if ((ret = quicly_connect(&client, &ctx, host, (struct sockaddr *)&sas, NULL, &next_cid, ptls_iovec_init(NULL, 0), NULL,
                                NULL)) != 0) {
        fprintf(stderr, "quicly_connect failed:%d\n", ret);
        exit(1);
    }
    quicly_stream_t *stream; /* we retain the opened stream via the on_stream_open callback */
    quicly_open_stream(client, &stream, 0);

    /* enter the event loop with a connection object */
    return run_loop_client(fd, client);
}
