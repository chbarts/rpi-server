/* Server code to run on the Raspberry Pi */

#include <linux/limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define GROUP "224.0.0.3"
#define BPORT 2015
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

static int sock = 0;

static void broadcaster(void)
{
    struct sockaddr_in addr;
    uint32_t data, crc;
    char message[sizeof(data) + sizeof(crc)];
    time_t mtime;
    int i;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("broadcaster couldn't make socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
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

#ifndef DEBUG
#define CMD "nc -kl -p 2025 | omxplayer -o hdmi rtsp://%s:8554/%s"
#define CMD2 "nc -kl -p 2025 | omxplayer -o hdmi rtsp://[%s]:8554/%s"
#else
#define CMD "echo 'nc -kl -p 2025 | omxplayer -o hdmi rtsp://%s:8554/%s'"
#define CMD2 "echo 'nc -kl -p 2025 | omxplayer -o hdmi rtsp://[%s]:8554/%s'"
#endif
#define BUF_LEN (sizeof(CMD2) + INET6_ADDRSTRLEN + PATH_MAX)

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

static void child(int cfd, struct sockaddr *sa)
{
    char buf[BUF_LEN], addr[INET6_ADDRSTRLEN], file[PATH_MAX];
    ssize_t len, totlen = 0;

    while ((len = read(cfd, file + totlen, PATH_MAX - totlen)) > 0) {
        totlen += len;
    }

    shutdown(cfd, SHUT_RDWR);
    close(cfd);
    file[totlen] = '\0';
    get_ip_str(sa, addr);
    if (sa->sa_family == AF_INET) {
        snprintf(buf, BUF_LEN, CMD, addr, file);
    } else {
        snprintf(buf, BUF_LEN, CMD2, addr, file);
    }

    system(buf);
    exit(EXIT_SUCCESS);
}

#define SPORT 1984

static pid_t bpid = 0, cpid = 0;
static int sfd = 0, cfd = 0;

static void handler(int sig)
{
    int i;

    if (sfd && cpid) {
        close(sfd);
    }

    if (cfd && !cpid) {
        shutdown(cfd, SHUT_RDWR);
        close(cfd);
    }

    if (sock && !bpid) {
        close(sock);
    }

    if (bpid && cpid) {
        waitpid(bpid, &i, 0);
        bpid = 0;
        waitpid(cpid, &i, 0);
        cpid = 0;
    }

    if (cpid) {
        waitpid(cpid, &i, 0);
    }

    if (!sock && bpid) {
        waitpid(bpid, &i, 0);
    }

    exit(EXIT_SUCCESS);
}

static int sig_handle(int sig, void (*hndlr) (int))
{
    struct sigaction act;

    act.sa_handler = hndlr;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(sig, &act, NULL) == -1) {
        return -1;
    }

    return 0;
}

int main(void)
{
    struct sockaddr_in sa;
    int i;
    socklen_t addrlen;

    if (sig_handle(SIGTERM, handler) == -1) {
        perror("sigaction() SIGTERM");
        exit(EXIT_FAILURE);
    }

    if ((sfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    addrlen = sizeof(sa);
    memset(&sa, 0, addrlen);
    sa.sin_family = PF_INET;
    sa.sin_port = htons(SPORT);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sfd, (const void *) &sa, sizeof(sa)) == -1) {
        perror("bind() failed");
        close(sfd);
        exit(EXIT_FAILURE);
    }

    if (listen(sfd, 50) == -1) {
        perror("listen() failed");
        close(sfd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        switch (bpid = fork()) {
        case 0:
            broadcaster();
            break;
        case -1:
            perror("fork() failed");
            close(sfd);
            exit(EXIT_FAILURE);
            break;
        default:
            break;
        }

        if ((cfd = accept(sfd, (struct sockaddr *) &sa, &addrlen)) == -1) {
            perror("accept() failed");
            close(sfd);
            kill(bpid, SIGKILL);
            waitpid(bpid, &i, 0);
            exit(EXIT_FAILURE);
        }

        switch (cpid = fork()) {
        case 0:
            child(cfd, (struct sockaddr *) &sa);
            break;
        case -1:
            perror("fork() failed");
            close(sfd);
            shutdown(cfd, SHUT_RDWR);
            close(cfd);
            kill(bpid, SIGKILL);
            waitpid(bpid, &i, 0);
            exit(EXIT_FAILURE);
            break;
        default:
            kill(bpid, SIGKILL);
            waitpid(bpid, &i, 0);
            bpid = 0;
            waitpid(cpid, &i, 0);
            break;
        }

        cpid = 0;
    }

    return 0;
}
