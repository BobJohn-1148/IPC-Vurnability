// server.c  —  SAFE server (bounds-checked)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define SOCKET_PATH    "/tmp/ipc_demo_socket"
#define CMD_SIZE       16
#define PAYLOAD_SIZE   128
#define LOCAL_BUF_SIZE 32

typedef struct {
    char command[CMD_SIZE];
    char payload[PAYLOAD_SIZE];
} IPCMessage;

void cleanup_socket(void) {
    unlink(SOCKET_PATH);
}

int main(void) {
    int server_fd, client_fd;
    struct sockaddr_un addr;
    IPCMessage msg;
    char local_buffer[LOCAL_BUF_SIZE];

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    unlink(SOCKET_PATH);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(server_fd); return 1;
    }
    if (listen(server_fd, 5) < 0) {
        perror("listen"); close(server_fd); cleanup_socket(); return 1;
    }

    printf("[safe-server] Listening on %s\n", SOCKET_PATH);
    printf("[safe-server] local_buffer is at address: %p\n", (void *)local_buffer);
    printf("[safe-server] local_buffer size: %d bytes\n", LOCAL_BUF_SIZE);
    fflush(stdout);

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) { perror("accept"); break; }

        ssize_t bytes = recv(client_fd, &msg, sizeof(msg), 0);
        if (bytes <= 0) {
            perror("recv");
            close(client_fd);
            continue;
        }

        msg.command[CMD_SIZE - 1]     = '\0';
        msg.payload[PAYLOAD_SIZE - 1] = '\0';

        printf("[safe-server] Command : %s\n", msg.command);
        printf("[safe-server] Payload : %s  (len=%zu)\n",
               msg.payload, strlen(msg.payload));

        if (strlen(msg.payload) >= (size_t)LOCAL_BUF_SIZE) {
            printf("[safe-server] Payload too large — rejected (max %d bytes).\n",
                   LOCAL_BUF_SIZE - 1);
            const char *resp = "ERROR: payload too large";
            send(client_fd, resp, strlen(resp) + 1, 0);
        } else {
            strcpy(local_buffer, msg.payload);
            printf("[safe-server] Safely stored: %s\n", local_buffer);
            const char *resp = "OK: message processed";
            send(client_fd, resp, strlen(resp) + 1, 0);
        }

        fflush(stdout);
        close(client_fd);
    }

    close(server_fd);
    cleanup_socket();
    return 0;
}
