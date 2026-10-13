#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>
#include <dirent.h>

#define PORT 9410
#define SID "552"
#define AUTH_TOKEN "OPS-2550"
#define STORAGE_PATH "./agentfiles/IT24102550"
#define BUFFER_SIZE 4096

// ============================================
// Logging function
// ============================================
void log_event(const char *format, ...) {
    FILE *log_fp = fopen("remoteops_IT24102550.log", "a");
    if (log_fp == NULL) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    fprintf(log_fp, "[%s] ", timestamp);

    va_list args;
    va_start(args, format);
    vfprintf(log_fp, format, args);
    va_end(args);

    fprintf(log_fp, "\n");
    fclose(log_fp);
}

void send_response(int client_fd, const char *msg) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "%s SID:%s\n", msg, SID);
    send(client_fd, buffer, strlen(buffer), 0);
}

// ============================================
// UDP Monitoring Globals + Thread
// ============================================
int monitoring_active = 0;
int monitor_client_fd = -1;
struct sockaddr_in monitor_udp_addr;
pthread_t monitor_tid;
pthread_mutex_t monitor_mutex = PTHREAD_MUTEX_INITIALIZER;

void *monitor_thread(void *arg) {
    (void)arg;
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket failed");
        return NULL;
    }

    printf("[Agent] UDP monitoring thread started\n");

    while (1) {
        pthread_mutex_lock(&monitor_mutex);
        if (!monitoring_active) {
            pthread_mutex_unlock(&monitor_mutex);
            break;
        }
        pthread_mutex_unlock(&monitor_mutex);

        struct sysinfo si;
        sysinfo(&si);
        double cpu_load = si.loads[0] / 65536.0;
        long mem_used_mb = (si.totalram - si.freeram) * si.mem_unit / (1024 * 1024);
        long uptime_sec = si.uptime;

        char udp_msg[512];
        snprintf(udp_msg, sizeof(udp_msg),
                 "SYSINFO %.2f %ld %ld SID:%s\n",
                 cpu_load, mem_used_mb, uptime_sec, SID);

        sendto(udp_sock, udp_msg, strlen(udp_msg), 0,
               (struct sockaddr *)&monitor_udp_addr, sizeof(monitor_udp_addr));

        printf("[Agent] UDP sent: %s", udp_msg);
        sleep(2);
    }

    close(udp_sock);
    printf("[Agent] UDP monitoring thread stopped\n");
    return NULL;
}

// ============================================
// Handle Client
// ============================================
void handle_client(int client_fd);

void *client_thread(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);
    handle_client(client_fd);
    return NULL;
}

void handle_client(int client_fd) {
    char buffer[BUFFER_SIZE];
    int authenticated = 0;

    printf("[Agent] New client connected\n");
    log_event("CONNECTION: New client connected (fd=%d)", client_fd);

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes = read(client_fd, buffer, BUFFER_SIZE - 1);
        if (bytes <= 0) {
            printf("[Agent] Client disconnected\n");
            log_event("DISCONNECT: Client (fd=%d)", client_fd);
            break;
        }

        buffer[strcspn(buffer, "\r\n")] = 0;
        printf("[Agent] Received: %s\n", buffer);
        log_event("CMD: %s (fd=%d)", buffer, client_fd);

        // Authentication
        if (!authenticated) {
            if (strncmp(buffer, "AUTH ", 5) == 0) {
                char *token = buffer + 5;
                if (strcmp(token, AUTH_TOKEN) == 0) {
                    authenticated = 1;
                    send_response(client_fd, "OK AUTHENTICATED");
                    printf("[Agent] Authentication successful\n");
                    log_event("AUTH: Successful for client (fd=%d)", client_fd);
                } else {
                    send_response(client_fd, "ERR 001 AUTH_FAILED");
                    printf("[Agent] Authentication failed\n");
                    log_event("AUTH: FAILED for client (fd=%d)", client_fd);
                }
            } else {
                send_response(client_fd, "ERR 001 AUTH_FAILED");
            }
            continue;
        }

        // SYSINFO
        if (strcmp(buffer, "SYSINFO") == 0) {
            struct sysinfo si;
            sysinfo(&si);
            double cpu_load = si.loads[0] / 65536.0;
            long mem_used_mb = (si.totalram - si.freeram) * si.mem_unit / (1024 * 1024);
            long uptime_sec = si.uptime;

            char response[BUFFER_SIZE];
            snprintf(response, sizeof(response),
                     "OK SYSINFO %.2f %ld %ld SID:%s\n",
                     cpu_load, mem_used_mb, uptime_sec, SID);
            send(client_fd, response, strlen(response), 0);
            printf("[Agent] SYSINFO sent: cpu=%.2f mem=%ldMB uptime=%lds\n",
                   cpu_load, mem_used_mb, uptime_sec);
            continue;
        }

        // LISTPROC
        if (strcmp(buffer, "LISTPROC") == 0) {
            FILE *fp = popen("ps -eo pid,comm --no-headers | head -20", "r");
            if (fp == NULL) {
                send_response(client_fd, "ERR 003 PROC_LIST_FAILED");
                continue;
            }

            char proc_list[BUFFER_SIZE / 2];
            memset(proc_list, 0, sizeof(proc_list));
            char line[256];
            int first = 1;

            while (fgets(line, sizeof(line), fp) != NULL) {
                line[strcspn(line, "\r\n")] = 0;
                char *p = line;
                while (*p == ' ') p++;

                if (!first) {
                    strncat(proc_list, ",", BUFFER_SIZE - strlen(proc_list) - 1);
                }
                strncat(proc_list, p, BUFFER_SIZE - strlen(proc_list) - 1);
                first = 0;
            }
            pclose(fp);

            char response[BUFFER_SIZE];
            snprintf(response, sizeof(response),
                     "OK PROCs %s SID:%s\n", proc_list, SID);
            send(client_fd, response, strlen(response), 0);
            printf("[Agent] LISTPROC sent: %d chars\n", (int)strlen(proc_list));
            continue;
        }

        // EXEC
        if (strncmp(buffer, "EXEC ", 5) == 0) {
            char *cmd_name = buffer + 5;
            char shell_cmd[256] = {0};
            int allowed = 1;

            if (strcmp(cmd_name, "DATE") == 0) {
                strcpy(shell_cmd, "date");
            } else if (strcmp(cmd_name, "UPTIME") == 0) {
                strcpy(shell_cmd, "uptime -p");
            } else if (strcmp(cmd_name, "DISKFREE") == 0) {
                strcpy(shell_cmd, "df -h / | tail -1");
            } else if (strcmp(cmd_name, "HOSTNAME") == 0) {
                strcpy(shell_cmd, "hostname");
            } else if (strcmp(cmd_name, "WHOAMI") == 0) {
                strcpy(shell_cmd, "whoami");
            } else {
                allowed = 0;
            }

            if (!allowed) {
                send_response(client_fd, "ERR 002 COMMAND_NOT_ALLOWED");
                printf("[Agent] EXEC rejected: %s\n", cmd_name);
                continue;
            }

            FILE *fp = popen(shell_cmd, "r");
            if (fp == NULL) {
                send_response(client_fd, "ERR 002 COMMAND_NOT_ALLOWED");
                continue;
            }

            char output[BUFFER_SIZE / 2];
            memset(output, 0, sizeof(output));
            char line[256];
            while (fgets(line, sizeof(line), fp) != NULL) {
                line[strcspn(line, "\r\n")] = 0;
                if (strlen(output) > 0) {
                    strncat(output, " ", BUFFER_SIZE - strlen(output) - 1);
                }
                strncat(output, line, BUFFER_SIZE - strlen(output) - 1);
            }
            pclose(fp);

            char response[BUFFER_SIZE];
            snprintf(response, sizeof(response),
                     "OK EXEC_RESULT %s SID:%s\n", output, SID);
            send(client_fd, response, strlen(response), 0);
            printf("[Agent] EXEC %s -> %s\n", cmd_name, output);
            continue;
        }

        // PUT
        if (strncmp(buffer, "PUT ", 4) == 0) {
            char filename[256];
            long filesize;
            sscanf(buffer + 4, "%255s %ld", filename, &filesize);

            mkdir("./agentfiles", 0755);
            mkdir(STORAGE_PATH, 0755);

            char filepath[512];
            snprintf(filepath, sizeof(filepath),
                     "%s/%s", STORAGE_PATH, filename);

            FILE *fp = fopen(filepath, "wb");
            if (fp == NULL) {
                send_response(client_fd, "ERR 004 FILE_TOO_LARGE");
                continue;
            }

            long received = 0;
            char filebuf[4096];
            while (received < filesize) {
                long to_read = filesize - received;
                if (to_read > (long)sizeof(filebuf)) to_read = sizeof(filebuf);
                int n = read(client_fd, filebuf, to_read);
                if (n <= 0) break;
                fwrite(filebuf, 1, n, fp);
                received += n;
            }
            fclose(fp);

            char response[BUFFER_SIZE];
            snprintf(response, sizeof(response),
                     "OK FILE_RECEIVED %s SID:%s\n", filename, SID);
            send(client_fd, response, strlen(response), 0);
            printf("[Agent] PUT: %s (%ld bytes)\n", filename, received);
            log_event("PUT: %s (%ld bytes) from fd=%d", filename, received, client_fd);
            continue;
        }

        // GET
        if (strncmp(buffer, "GET ", 4) == 0) {
            char filename[256];
            sscanf(buffer + 4, "%255s", filename);

            char filepath[512];
            snprintf(filepath, sizeof(filepath),
                     "%s/%s", STORAGE_PATH, filename);

            FILE *fp = fopen(filepath, "rb");
            if (fp == NULL) {
                send_response(client_fd, "ERR 005 FILE_NOT_FOUND");
                continue;
            }

            fseek(fp, 0, SEEK_END);
            long filesize = ftell(fp);
            fseek(fp, 0, SEEK_SET);

            char header[512];
            snprintf(header, sizeof(header),
                     "OK FILE_SEND %s %ld SID:%s\n", filename, filesize, SID);
            send(client_fd, header, strlen(header), 0);

            char filebuf[4096];
            long sent = 0;
            int n;
            while ((n = fread(filebuf, 1, sizeof(filebuf), fp)) > 0) {
                send(client_fd, filebuf, n, 0);
                sent += n;
            }
            fclose(fp);

            printf("[Agent] GET: %s (%ld bytes)\n", filename, sent);
            log_event("GET: %s (%ld bytes) to fd=%d", filename, sent, client_fd);
            continue;
        }

        // LIST
        if (strcmp(buffer, "LIST") == 0) {
            DIR *dir = opendir(STORAGE_PATH);
            if (dir == NULL) {
                send_response(client_fd, "OK FILES 0 NONE");
                printf("[Agent] LIST: 0 files (folder missing)\n");
                log_event("LIST: 0 files (NONE) from fd=%d", client_fd);
                continue;
            }

            struct dirent *entry;
            char file_list[BUFFER_SIZE];
            file_list[0] = '\0';
            int count = 0;

            while ((entry = readdir(dir)) != NULL) {
                // Skip . and ..
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                    continue;
                }

                char fullpath[1024];
                snprintf(fullpath, sizeof(fullpath), "%s/%s", STORAGE_PATH, entry->d_name);

                struct stat st;
                if (stat(fullpath, &st) == -1) {
                    continue;
                }

                // Skip any sub-folders (only include regular files)
                if (!S_ISREG(st.st_mode)) {
                    continue;
                }

                char item[512];
                snprintf(item, sizeof(item), "%s:%ld", entry->d_name, (long)st.st_size);

                if (count > 0) {
                    strncat(file_list, ",", sizeof(file_list) - strlen(file_list) - 1);
                }
                strncat(file_list, item, sizeof(file_list) - strlen(file_list) - 1);
                count++;
            }
            closedir(dir);

            if (count == 0) {
                send_response(client_fd, "OK FILES 0 NONE");
                printf("[Agent] LIST: 0 files (empty)\n");
                log_event("LIST: 0 files (NONE) from fd=%d", client_fd);
            } else {
                char response[BUFFER_SIZE];
                snprintf(response, sizeof(response), "OK FILES %d %s", count, file_list);
                send_response(client_fd, response);
                printf("[Agent] LIST sent: %d files (%s)\n", count, file_list);
                log_event("LIST: %d files (%s) from fd=%d", count, file_list, client_fd);
            }
            continue;
        }

        // MONITOR START
        if (strncmp(buffer, "MONITOR START ", 14) == 0) {
            int udp_port = atoi(buffer + 14);

            pthread_mutex_lock(&monitor_mutex);
            if (monitoring_active) {
                pthread_mutex_unlock(&monitor_mutex);
                send_response(client_fd, "ERR 006 MONITOR_ALREADY_ACTIVE");
                continue;
            }

            monitor_udp_addr.sin_family = AF_INET;
            monitor_udp_addr.sin_port = htons(udp_port);
            monitor_udp_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

            monitoring_active = 1;
            monitor_client_fd = client_fd;
            pthread_mutex_unlock(&monitor_mutex);

            pthread_create(&monitor_tid, NULL, monitor_thread, NULL);
            pthread_detach(monitor_tid);

            send_response(client_fd, "OK MONITOR_STARTED");
            printf("[Agent] Monitoring started -> UDP port %d\n", udp_port);
            continue;
        }

        // MONITOR STOP
        if (strcmp(buffer, "MONITOR STOP") == 0) {
            pthread_mutex_lock(&monitor_mutex);
            monitoring_active = 0;
            pthread_mutex_unlock(&monitor_mutex);

            send_response(client_fd, "OK MONITOR_STOPPED");
            printf("[Agent] Monitoring stopped\n");
            continue;
        }

        // QUIT
        if (strcmp(buffer, "QUIT") == 0) {
            send_response(client_fd, "OK BYE");
            break;
        } else {
            send_response(client_fd, "ERR 002 COMMAND_NOT_ALLOWED");
        }
    }
    close(client_fd);
}

int main() {
    log_event("=== Agent STARTED (port=%d, SID=%s) ===", PORT, SID);

    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("socket failed");
        exit(1);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(1);
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        exit(1);
    }

    printf("========================================\n");
    printf("RemoteOps Agent (IT24102550)\n");
    printf("Listening on port %d\n", PORT);
    printf("SID: %s\n", SID);
    printf("Auth token: %s\n", AUTH_TOKEN);
    printf("========================================\n");

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }

        int *new_fd = malloc(sizeof(int));
        *new_fd = client_fd;

        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, new_fd) != 0) {
            perror("pthread_create failed");
            close(client_fd);
            free(new_fd);
            continue;
        }
        pthread_detach(tid);
        printf("[Agent] Spawned thread for client (fd=%d)\n", client_fd);
    }

    close(server_fd);
    return 0;
}
