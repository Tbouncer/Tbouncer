#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "tst_test.h"
#include "tst_safe_net.h"
#include "tst_safe_pthread.h"

#define LOCALHOSTIP "127.0.0.1"
#define SWITCH_FILE "/dev/shm/switch_file"

static int server_sockfd;
static int client_sockfd;
static int server_port;
static socklen_t addr_len;

static struct sockaddr_in *server_addr;
static struct sockaddr_in *client_addr;

static void *server_thread(void *arg)
{
    server_sockfd = SAFE_SOCKET(AF_INET, SOCK_STREAM, 0);

    SAFE_SETSOCKOPT(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    SAFE_BIND(server_sockfd, (struct sockaddr *)server_addr, addr_len);
    SAFE_LISTEN(server_sockfd, 1);

    TST_CHECKPOINT_WAKE(0);

    while (1) {
        TEST(accept(server_sockfd, (struct sockaddr *)client_addr, &addr_len));
        if (TST_RET == -1) {
            if (errno == EINTR) continue; // Interrupted by signal, retry
            tst_brk(TBROK | TTERRNO, "Could not accept connection");
        }

        if (TST_RET != -1 && TST_RET < 0) {
            tst_res(TPASS, "accept() returned invalid fd %d, attack succeeded", TST_RET);
            SAFE_CLOSE(server_sockfd);
            return NULL;
        }

        tst_res(TINFO, "Accepted connection on fd %d", TST_RET);
        SAFE_CLOSE(TST_RET); // Close the accepted client socket
    }

    SAFE_CLOSE(server_sockfd);
    return NULL;
}

static void *client_thread(void *arg)
{
    client_sockfd = SAFE_SOCKET(AF_INET, SOCK_STREAM, 0);
    SAFE_BIND(client_sockfd, (struct sockaddr *)client_addr, addr_len);

    SAFE_CONNECT(client_sockfd, (struct sockaddr *)server_addr, addr_len);
    SAFE_SEND(1, client_sockfd, "Hello from client!", 18, 0);
    tst_res(TINFO, "Message sent from client");
    SAFE_CLOSE(client_sockfd);

    return NULL;
}

static void run(void)
{
    pthread_t server_thr, client_thr;

    server_addr->sin_port = server_port;
    client_addr->sin_port = htons(0);

    // Write the coordination file to indicate the attack scenario
    write_coordination_file("iago_attack_accept");

    SAFE_PTHREAD_CREATE(&server_thr, NULL, server_thread, NULL);
    TST_CHECKPOINT_WAIT(0);
    SAFE_PTHREAD_CREATE(&client_thr, NULL, client_thread, NULL);

    SAFE_PTHREAD_JOIN(server_thr, NULL);
    SAFE_PTHREAD_JOIN(client_thr, NULL);
    sleep(10);
    // Reset the coordination file after completion
    write_coordination_file("0");
}

static void setup(void)
{
    server_addr = tst_alloc(sizeof(*server_addr));
    client_addr = tst_alloc(sizeof(*client_addr));

    server_addr->sin_family = AF_INET;
    inet_aton(LOCALHOSTIP, &server_addr->sin_addr);

    client_addr->sin_family = AF_INET;
    client_addr->sin_addr.s_addr = htonl(INADDR_ANY);

    addr_len = sizeof(struct sockaddr_in);

    server_port = TST_GET_UNUSED_PORT(AF_INET, SOCK_STREAM);
    tst_res(TINFO, "Starting listener on port: %d", ntohs(server_port));
}

static void cleanup(void)
{
    if (client_sockfd > 0)
        SAFE_CLOSE(client_sockfd);
    if (server_sockfd > 0)
        SAFE_CLOSE(server_sockfd);
}

static struct tst_test test = {
    .test_all = run,
    .setup = setup,
    .cleanup = cleanup,
    .needs_checkpoints = 1,
    .tags = (const struct tst_tag[]) {
        {"Category", "Network"},
        {"Subcategory", "Socket"},
        {},
    }
};
