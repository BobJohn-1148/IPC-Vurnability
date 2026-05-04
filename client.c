// client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/ipc_demo_socket"
#define CMD_SIZE 16
#define PAYLOAD_SIZE 128

typedef struct {
    char command[CMD_SIZE];
    char payload[PAYLOAD_SIZE];
} IPCMessage;

int main(int argc, char *argv[]) {
    int sock_fd;
    struct sockaddr_un addr;
    IPCMessage msg;
    char response[128];

    // Usage: ./client <command> <payload> [socket_path]
    // Default socket connects to the safe server.
    // Pass /tmp/ipc_vuln_socket as the third arg to target server_vuln.
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <command> <payload> [socket_path]\n", argv[0]);
        fprintf(stderr, "  Default socket: %s  (safe server)\n", SOCKET_PATH);
        fprintf(stderr, "  Vuln socket:    /tmp/ipc_vuln_socket\n");
        return 1;
    }

    const char *socket_path = (argc == 4) ? argv[3] : SOCKET_PATH;

    memset(&msg, 0, sizeof(msg));
    snprintf(msg.command, sizeof(msg.command), "%s", argv[1]);
    snprintf(msg.payload, sizeof(msg.payload), "%s", argv[2]);

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock_fd);
        return 1;
    }

    if (send(sock_fd, &msg, sizeof(msg), 0) < 0) {
        perror("send");
        close(sock_fd);
        return 1;
    }

    ssize_t bytes = recv(sock_fd, response, sizeof(response) - 1, 0);
    if (bytes > 0) {
        response[bytes] = '\0';
        printf("[client] Server response: %s\n", response);
    } else {
        perror("recv");
    }

    close(sock_fd);
    return 0;
}