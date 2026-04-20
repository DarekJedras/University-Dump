// Dariusz Jędras 347657

#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <time.h>


void ERROR(const char* str){
    fprintf(stderr, "%s: %s\n", str, strerror(errno));  // NOLINT(*-err33-c)
    exit(EXIT_FAILURE);
}

int get_timediff_ms(struct timespec *t1, struct timespec *t2){
    int result = (t1->tv_sec - t2->tv_sec) * 1000;
    result += (t1->tv_nsec - t2->tv_nsec) /1000000;
    return result;
}

uint16_t compute_icmp_checksum(const void *buff, int length){
    const u_int16_t* ptr = buff;
    u_int32_t sum = 0;
    assert (length % 2 == 0);
    for (; length > 0; length -= 2)
        sum += *ptr++;
    sum = (sum >> 16U) + (sum & 0xffffU);
    return ~(sum + (sum >> 16U));
}


// sends N icmp packets to IP_ADDR address with given ttl, icd_id and icd_seq set.
void send_icmp_requests(int n, int fd, in_addr_t ip_addr, int ttl, uint16_t id, uint16_t seq){

    struct icmphdr header;
    header.type = ICMP_ECHO;
    header.code = 0;
    header.un.echo.id = id;
    header.un.echo.sequence = seq;
    header.checksum = 0;
    header.checksum = compute_icmp_checksum((u_int16_t*)&header, sizeof(header));

    struct sockaddr_in recipient = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = ip_addr
    };

    int status = setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
    if (status < 0)
        ERROR("setsockopt error");
        
    for (int i = 0; i<n; i++) {
        ssize_t bytes_sent = sendto(
            fd,
            &header,
            sizeof(header),
            0,
            (struct sockaddr*)&recipient,
            sizeof(recipient)
        );

        if (bytes_sent < 0)
            ERROR("sendto error");
    }
}

// tries to read N icmp replies containing icd_id equal to ID from FD file descriptor,
// stores receival times and src ip addresses in given tables.
int get_icmp_replies(int n, int fd, uint16_t id, uint16_t seq, in_addr_t ip_addrs[], struct timespec receive_times[]){

    struct pollfd ps = {
        .fd = fd,
        .events = POLLIN,
        .revents = 0
    };

    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    u_int8_t buffer[IP_MAXPACKET];

    struct timespec start_time, current_time;
    int answers_cnt = 0, time_left = 1000;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    int echo_reply_received = 0;

    while (answers_cnt < n){
        int ready = poll(&ps, 1, time_left);
        if (ready < 0)
            ERROR("poll error");

        else if (ready == 0) {
            return answers_cnt;
        }

        clock_gettime(CLOCK_MONOTONIC, &current_time);
        time_left = 1000 - get_timediff_ms(&current_time, &start_time);
        if (time_left < 0)
            time_left = 0;
        
        if ((ps.revents & POLLIN) == 0)
            continue;

        // EWOULDBLOCK cant happen since we check in poll whether there is data to read
        ssize_t packet_len = recvfrom(fd, buffer, IP_MAXPACKET, MSG_DONTWAIT, (struct sockaddr*)&sender, &sender_len);
        if (packet_len < 0)
            ERROR("recvfrom error");

        struct iphdr* ip_header = (struct ip*) buffer;
        ssize_t ip_header_len = 4 * ip_header->ihl;

        struct icmphdr *icmp_header = (struct icmp*)(buffer + ip_header_len);
        struct icmphdr *icmp_proper_header;
        uint16_t packet_id, packet_seq;

        if (icmp_header->type == ICMP_ECHOREPLY){
            icmp_proper_header = icmp_header;
            echo_reply_received = 1;
        }
        else if (icmp_header->type == ICMP_TIME_EXCEEDED){
            struct iphdr* inner_ip_header = (struct ip*)((uint8_t*)icmp_header + 8);
            ssize_t inner_ip_header_len = 4 * inner_ip_header->ihl;
            icmp_proper_header = (struct icmp*)(buffer + ip_header_len + 8 + inner_ip_header_len);
        }
        else
            continue;
            
        packet_id = icmp_proper_header->un.echo.id;
        packet_seq = icmp_proper_header->un.echo.sequence;
        
        if (packet_id == id && packet_seq == seq){
            ip_addrs[answers_cnt] = sender.sin_addr.s_addr;
            receive_times[answers_cnt] = current_time;
            answers_cnt++;
        }
    }
    if (echo_reply_received) return -answers_cnt;
    return answers_cnt;
}


void print_traceroute_step(int packets_count, in_addr_t ip_addrs[], struct timespec *send_time, struct timespec receive_times[], int step){
    printf("%d. ", step);

    if (packets_count == 0)
        printf("*\n");
    else {
        for (int i = 0; i<packets_count; i++){
            int is_unique = 1;
            for (int j = 0; j<i; j++)
                is_unique &= (ip_addrs[i] != ip_addrs[j]);
            
            if (is_unique){
                char ip_str[20];
                const char *status = inet_ntop(AF_INET, &ip_addrs[i], ip_str, sizeof(ip_str));
                if (status == NULL)
                    ERROR("inet_ntop error");
                
                printf("%s ", ip_str);
            }
        }

        if (packets_count == 3){
            int avg_time = 0;
            for (int i = 0; i<packets_count; i++)
                avg_time += get_timediff_ms(&receive_times[i], send_time);

            avg_time /= 3;
            printf("%d ms\n", avg_time);
        }
        else {
            printf("???\n");
        }
    }
}


int main(int argc, char *argv[]){
    if (argc != 2) {
        printf("argument error: Expected exactly one argument (Destination IP Address)\n");
        exit(EXIT_FAILURE);
    }

    in_addr_t dest_ip;
    int translation_status = inet_pton(AF_INET, argv[1], &dest_ip);
    if (translation_status == 0){
        printf("argument error: Invalid IP format\n");
        exit(EXIT_FAILURE);
    }

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0)
        ERROR("socket error");

    uint16_t id = (uint16_t)getpid();

    struct timespec send_time;
    struct timespec receive_times[3];
    in_addr_t ip_addrs[3];

    for (int ttl = 1; ttl < 31; ttl++) {
        send_icmp_requests(3, sockfd, dest_ip, ttl, id, ttl);
        clock_gettime(CLOCK_MONOTONIC, &send_time);

        int answers_count = get_icmp_replies(3, sockfd, id, ttl, ip_addrs, receive_times);
        if (answers_count < 0){
            print_traceroute_step(-answers_count, ip_addrs, &send_time, receive_times, ttl);
            break;
        }
        else {
            print_traceroute_step(answers_count, ip_addrs, &send_time, receive_times, ttl);
        }
    }

    close(sockfd);
    return 0;
}

