#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <strings.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define GROUP "224.0.0.3"
#define BPORT 2015
#define KEY   0xdeadbeef
#define MOD   65521

static uint32_t adler32(uint32_t data)
{
    uint8_t *dp, buf[sizeof(data) + sizeof(KEY)];
    uint32_t a = 1, b = 0;
    int i, len = sizeof(data) + sizeof(KEY);

    dp = (uint32_t *) & data;

    for (i = 0; i < sizeof(data); i++) {
        buf[i] = dp[i];
    }

    buf[i++] = 0xde;
    buf[i++] = 0xad;
    buf[i++] = 0xbe;
    buf[i++] = 0xef;

    for (i = 0; i < len; i++) {
        a = (a + buf[i]) % MOD;
        b = (b + a) % MOD;
    }

    return (b << 16) | a;
}

static void broadcaster(void)
{
    struct sockaddr_in addr;
    uint32_t data, crc;
    char message[sizeof(data) + sizeof(crc)];
    time_t mtime;
    int i, sock;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("broadcaster couldn't make socket");
        exit(EXIT_FAILURE);
    }

    bzero((char *) &addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BPORT);
    addr.sin_addr.s_addr = inet_addr(GROUP);

    while (1) {
        if ((mtime = time(NULL)) == ((time_t) - 1)) {
            perror("broadcaster couldn't get time");
            exit(EXIT_FAILURE);
        }

        data = htonl((int32_t) mtime);  /* Drop 64 most significant bits */
        crc = htonl(adler32(data));
        for (i = 0; i < sizeof(data); i++) {
            message[i] = ((char *) (&data))[i];
        }

        for (i = 0; i < sizeof(crc); i++) {
            message[sizeof(data) + i] = ((char *) (&crc))[i];
        }

        if (sendto
            (sock, message, sizeof(message), 0, (struct sockaddr *) &addr,
             sizeof(addr)) < 0) {
            perror("broadcaster couldn't broadcast");
            exit(EXIT_FAILURE);
        }

        sleep(1);
    }
}
