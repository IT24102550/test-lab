#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#define PORT 9410
#define SERVER_IP "127.0.0.1"
#define AUTH_TOKEN "OPS-2550"
#define BUFFER_SIZE 4096
#define UDP_PORT 9999

void *udp_receiver(void *arg) {
    (void)arg;
    int udp_sock;
    struct sockaddr_in udp_addr;
    char buffer[1024];

    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket failed");
        return NULL;
    }

    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = INADDR_ANY;
    udp_addr.sin_port = htons(UDP_PORT);

    if (bind(udp_sock, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) < 0) {
        perror("UDP bind failed");
        close(udp_sock);
        return NULL;
    }

    printf("[Controller] UDP listener on port %d\n", UDP_PORT);

    for (int i = 0; i < 5; i++) {
        memset(buffer, 0, sizeof(buffer));
        int n = recvfrom(udp_sock, buffer, sizeof(buffer) - 1, 0, NULL, NULL);
        if (n > 0) {
            printf("[Controller] UDP Received: %s", buffer);
        }
    }

    close(udp_sock);
    return NULL;
}

int main() {
    int sock;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    // ============================================
    // Test: Lockout & Concurrent Connections
    // ============================================
    printf("============================================================\n");
    printf("[Test] Testing AUTH Lockout & Concurrent Client Access\n");
    printf("============================================================\n");

    int sock1 = socket(AF_INET, SOCK_STREAM, 0);
    if (sock1 < 0 || connect(sock1, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("sock1 connect failed");
        exit(1);
    }
    printf("[Client 1] Connected to Agent on port %d\n", PORT);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0 || connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("sock2 connect failed");
        exit(1);
    }
    printf("[Client 2 (Controller)] Connected to Agent concurrently on port %d\n", PORT);

    // Client 1 - Attempt 1 (Failure)
    send(sock1, "AUTH BAD_TOKEN_1\n", 17, 0);
    printf("[Client 1] Sent: AUTH BAD_TOKEN_1\n");
    memset(buffer, 0, BUFFER_SIZE);
    read(sock1, buffer, BUFFER_SIZE - 1);
    printf("[Client 1] Received: %s", buffer);

    // Client 2 - Legitimate login at the same time (Requirement 3)
    char auth_cmd[100];
    snprintf(auth_cmd, sizeof(auth_cmd), "AUTH %s\n", AUTH_TOKEN);
    send(sock, auth_cmd, strlen(auth_cmd), 0);
    printf("[Client 2] Sent: %s", auth_cmd);
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE - 1);
    printf("[Client 2] Received: %s", buffer);

    // Client 1 - Attempt 2 (Failure)
    send(sock1, "AUTH BAD_TOKEN_2\n", 17, 0);
    printf("[Client 1] Sent: AUTH BAD_TOKEN_2\n");
    memset(buffer, 0, BUFFER_SIZE);
    read(sock1, buffer, BUFFER_SIZE - 1);
    printf("[Client 1] Received: %s", buffer);

    // Client 1 - Attempt 3 (Reaches limit - Requirement 2)
    send(sock1, "AUTH BAD_TOKEN_3\n", 17, 0);
    printf("[Client 1] Sent: AUTH BAD_TOKEN_3\n");
    memset(buffer, 0, BUFFER_SIZE);
    read(sock1, buffer, BUFFER_SIZE - 1);
    printf("[Client 1] Received: %s", buffer);

    // Verify Client 1 connection is closed by agent
    int r = read(sock1, buffer, BUFFER_SIZE - 1);
    if (r <= 0) {
        printf("[Client 1] Verified: Connection CLOSED by Agent after reaching limit! (Requirement 2)\n");
    }
    close(sock1);

    printf("============================================================\n");
    printf("[Client 2] Proceeding with normal operations (Requirement 3)\n");
    printf("============================================================\n");

    // SYSINFO
    send(sock, "SYSINFO\n", 8, 0);
    printf("[Controller] Sent: SYSINFO\n");
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE - 1);
    printf("[Controller] Received: %s", buffer);

    // LISTPROC
    send(sock, "LISTPROC\n", 9, 0);
    printf("[Controller] Sent: LISTPROC\n");
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE - 1);
    printf("[Controller] Received: %s", buffer);

    // EXEC DATE
    send(sock, "EXEC DATE\n", 10, 0);
    printf("[Controller] Sent: EXEC DATE\n");
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE - 1);
    printf("[Controller] Received: %s", buffer);

    // EXEC WHOAMI
    send(sock, "EXEC WHOAMI\n", 12, 0);
    printf("[Controller] Sent: EXEC WHOAMI\n");
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE - 1);
    printf("[Controller] Received: %s", buffer);

    // EXEC RM_RF (rejected)
    send(sock, "EXEC RM_RF\n", 11, 0);
    printf("[Controller] Sent: EXEC RM_RF\n");
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE - 1);
    printf("[Controller] Received: %s", buffer);

    // ============================================
    // Test (1): LIST when empty
    // ============================================
    send(sock, "LIST\n", 5, 0);
    printf("[Controller] Sent: LIST\n");
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE - 1);
    printf("[Controller] Received: %s", buffer);

    // ============================================
    // Test (2): Two PUTs then LIST with right sizes
    // ============================================
    // PUT 1: test_upload.txt
    FILE *test_fp = fopen("test_upload.txt", "wb");
    if (test_fp != NULL) {
        fprintf(test_fp, "Hello RemoteOps! This is a test file.\n");
        fclose(test_fp);
    }

    test_fp = fopen("test_upload.txt", "rb");
    if (test_fp != NULL) {
        fseek(test_fp, 0, SEEK_END);
        long file_size = ftell(test_fp);
        fseek(test_fp, 0, SEEK_SET);

        char put_cmd[256];
        snprintf(put_cmd, sizeof(put_cmd), "PUT test_upload.txt %ld\n", file_size);
        send(sock, put_cmd, strlen(put_cmd), 0);
        printf("[Controller] Sent: %s", put_cmd);

        char filebuf[4096];
        int n;
        while ((n = fread(filebuf, 1, sizeof(filebuf), test_fp)) > 0) {
            send(sock, filebuf, n, 0);
        }
        fclose(test_fp);
        printf("[Controller] Sent file bytes\n");

        memset(buffer, 0, BUFFER_SIZE);
        read(sock, buffer, BUFFER_SIZE - 1);
        printf("[Controller] Received: %s", buffer);
    }

    // PUT 2: sample_550.txt
    FILE *test_fp2 = fopen("sample_550.txt", "wb");
    if (test_fp2 != NULL) {
        fprintf(test_fp2, "RemoteOps second sample file for LIST verification!\n");
        fclose(test_fp2);
    }

    test_fp2 = fopen("sample_550.txt", "rb");
    if (test_fp2 != NULL) {
        fseek(test_fp2, 0, SEEK_END);
        long file_size2 = ftell(test_fp2);
        fseek(test_fp2, 0, SEEK_SET);

        char put_cmd2[256];
        snprintf(put_cmd2, sizeof(put_cmd2), "PUT sample_550.txt %ld\n", file_size2);
        send(sock, put_cmd2, strlen(put_cmd2), 0);
        printf("[Controller] Sent: %s", put_cmd2);

        char filebuf[4096];
        int n;
        while ((n = fread(filebuf, 1, sizeof(filebuf), test_fp2)) > 0) {
            send(sock, filebuf, n, 0);
        }
        fclose(test_fp2);
        printf("[Controller] Sent file bytes\n");

        memset(buffer, 0, BUFFER_SIZE);
        read(sock, buffer, BUFFER_SIZE - 1);
        printf("[Controller] Received: %s", buffer);
    }

    // LIST after two PUTs
    send(sock, "LIST\n", 5, 0);
    printf("[Controller] Sent: LIST\n");
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE - 1);
    printf("[Controller] Received: %s", buffer);

    // GET
    send(sock, "GET test_upload.txt\n", 20, 0);
    printf("[Controller] Sent: GET test_upload.txt\n");
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE - 1);
    printf("[Controller] Received: %s", buffer);

    long recv_size = 0;
    sscanf(buffer, "OK FILE_SEND %*s %ld", &recv_size);

    FILE *recv_fp = fopen("test_downloaded.txt", "wb");
    long total = 0;
    char recvbuf[4096];
    while (total < recv_size) {
        long to_read = recv_size - total;
        if (to_read > (long)sizeof(recvbuf)) to_read = sizeof(recvbuf);
        int r = read(sock, recvbuf, to_read);
        if (r <= 0) break;
        fwrite(recvbuf, 1, r, recv_fp);
        total += r;
    }
    fclose(recv_fp);
    printf("[Controller] Downloaded %ld bytes to test_downloaded.txt\n", total);

    // UDP Monitor
    pthread_t udp_tid;
    pthread_create(&udp_tid, NULL, udp_receiver, NULL);
    sleep(1);

    char monitor_cmd[64];
    snprintf(monitor_cmd, sizeof(monitor_cmd), "MONITOR START %d\n", UDP_PORT);
    send(sock, monitor_cmd, strlen(monitor_cmd), 0);
    printf("[Controller] Sent: %s", monitor_cmd);

    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE - 1);
    printf("[Controller] Received: %s", buffer);

    printf("[Controller] Waiting for UDP datagrams...\n");
    sleep(11);

    send(sock, "MONITOR STOP\n", 13, 0);
    printf("[Controller] Sent: MONITOR STOP\n");
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE - 1);
    printf("[Controller] Received: %s", buffer);

    pthread_join(udp_tid, NULL);

    // QUIT
    send(sock, "QUIT\n", 5, 0);
    printf("[Controller] Sent: QUIT\n");
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE - 1);
    printf("[Controller] Received: %s", buffer);

    close(sock);
    printf("[Controller] Disconnected\n");
    return 0;
}
