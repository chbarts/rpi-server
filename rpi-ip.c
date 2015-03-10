/* Code that automatically prints the IP address of the Raspberry Pi running the server software. */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define MOD   65521

static uint8_t key[] = { 0xde, 0xad, 0xbe, 0xef };

static uint32_t adler32(uint32_t data)
{
    uint8_t *dp, buf[sizeof(data) + sizeof(key)];
    uint32_t a = 1, b = 0;
    int i, len = sizeof(data) + sizeof(key);

    dp = (uint8_t *) & data;

    for (i = 0; i < sizeof(data); i++) {
        buf[i] = dp[i];
    }

    for (i = 0; i < sizeof(key); i++) {
        buf[sizeof(data) + i] = key[i];
    }

    for (i = 0; i < len; i++) {
        a = (a + buf[i]) % MOD;
        b = (b + a) % MOD;
    }

    return (b << 16) | a;
}

static void get_ip_str(const struct sockaddr *sa, char *addr)
{
    switch (sa->sa_family) {
    case AF_INET:
        inet_ntop(AF_INET, &(((struct sockaddr_in *) sa)->sin_addr), addr,
                  INET6_ADDRSTRLEN);
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) sa)->sin6_addr),
                  addr, INET6_ADDRSTRLEN);
        break;
    }
}

#define GROUP "224.0.0.3"
#define BPORT 2015

int main(void)
{
    struct sockaddr_in addr;
    struct ip_mreq mreq;
    uint32_t data, crc;
    socklen_t addrlen;
    char message[sizeof(data) + sizeof(crc)], addrstr[INET6_ADDRSTRLEN];
    int sock, ret;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket() failed");
        exit(EXIT_SUCCESS);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BPORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addrlen = sizeof(addr);

    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind() failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    mreq.imr_multiaddr.s_addr = inet_addr(GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt
        (sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt() failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (recvfrom
        (sock, message, sizeof(message), 0, (struct sockaddr *) &addr,
         &addrlen) != (sizeof(data) + sizeof(crc))) {
        perror("recvfrom() failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    close(sock);

    data = *(uint32_t *) message;
    crc = *(uint32_t *) (message + 4);

    if (crc != htonl(adler32(data))) {
        fprintf(stderr, "0x%x != 0x%x (0x%x 0x%x)\n", crc,
                htonl(adler32(data)), data, crc);
        exit(EXIT_FAILURE);
    }

    get_ip_str((struct sockaddr *) &addr, addrstr);
    puts(addrstr);
    return 0;
}
