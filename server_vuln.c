// server_vuln.c
// EDUCATIONAL USE ONLY — Intentionally vulnerable to buffer overflow.
// Demonstrates what happens when strcpy is used without bounds checking.
//
// Compile with stack protections DISABLED:
//   gcc -fno-stack-protector -z execstack -no-pie -o server_vuln server_vuln.c
//
// Run alongside client.c (compiled normally):
//   gcc -o client client.c
//   ./server_vuln &
//   ./client HELLO "short payload"          <- safe input
//   ./client HELLO "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  <- overflow input

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/ipc_vuln_socket"
#define CMD_SIZE    16
#define PAYLOAD_SIZE 128

// LOCAL_BUF_SIZE is intentionally small — only 32 bytes.
// Any payload longer than 31 characters will overflow it.
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

    // local_buffer lives on the stack — only 32 bytes allocated.
    // Overflowing it corrupts adjacent stack memory (saved registers,
    // return address, etc.), which can crash the process or redirect execution.
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

    printf("[vuln-server] Listening on %s\n", SOCKET_PATH);
    printf("[vuln-server] local_buffer is at address: %p\n", (void *)local_buffer);
    printf("[vuln-server] local_buffer size: %d bytes\n", LOCAL_BUF_SIZE);

    // Accept connections in a loop so repeated test runs don't need restart.
    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("accept");
            break;
        }

        ssize_t bytes = recv(client_fd, &msg, sizeof(msg), 0);
        if (bytes <= 0) {
            perror("recv");
            close(client_fd);
            continue;
        }

        msg.command[CMD_SIZE - 1]     = '\0';
        msg.payload[PAYLOAD_SIZE - 1] = '\0';

        printf("[vuln-server] Command : %s\n", msg.command);
        printf("[vuln-server] Payload : %s  (len=%zu)\n",
               msg.payload, strlen(msg.payload));
        printf("[vuln-server] Buffer  : %d bytes available\n", LOCAL_BUF_SIZE);

        // -------------------------------------------------------
        // VULNERABILITY: NO bounds check before strcpy.
        // If strlen(msg.payload) >= LOCAL_BUF_SIZE, this overflows
        // local_buffer and corrupts the stack.
        // -------------------------------------------------------
        strcpy(local_buffer, msg.payload);

        printf("[vuln-server] Stored in local_buffer: %s\n", local_buffer);

        const char *resp = "OK: message stored (may have overflowed!)";
        send(client_fd, resp, strlen(resp) + 1, 0);

        close(client_fd);
    }

    close(server_fd);
    cleanup_socket();
    return 0;
}
