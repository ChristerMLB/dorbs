// Define a feature test macro to expose modern POSIX functions
// This must be the very first thing in the file, before any #includes
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <ctype.h> // For isxdigit
#include <sys/time.h> // For struct timeval

#define DEFAULT_PORT 9001
#define BUFFER_SIZE 4096
#define MAX_FILES 100
#define MAX_FILE_SIZE (5 * 1024 * 1024)  // 5MB limit
#define MAX_PATH_LENGTH 255
#define MAX_TOTAL_CACHE_MEMORY (50 * 1024 * 1024)  // 50MB limit
#define THREAD_POOL_SIZE 8
#define REQUEST_QUEUE_SIZE 256
#define RATE_LIMIT_WINDOW 60  // seconds
#define MAX_REQUESTS_PER_IP 100
#define RATE_LIMIT_BUCKETS 128
#define CLEANUP_INTERVAL 1000 // Clean up rate limiter every 1000 requests

typedef struct {
    char name[256];
    char *data;
    size_t size;
    time_t last_access;
} FileCache;

typedef struct {
    int client_socket;
    struct sockaddr_storage client_addr;
} ClientRequest;

typedef struct RateLimitEntry {
    char ip[INET6_ADDRSTRLEN];
    int request_count;
    time_t window_start;
    struct RateLimitEntry *next;
} RateLimitEntry;

// --- Global state ---
FileCache caches[MAX_FILES];
int cache_count = 0;
size_t total_cache_memory = 0;
pthread_rwlock_t cache_rwlock = PTHREAD_RWLOCK_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Rate limiting
RateLimitEntry *rate_limit_table[RATE_LIMIT_BUCKETS];
pthread_mutex_t rate_limit_mutexes[RATE_LIMIT_BUCKETS];

// Thread pool and request queue
pthread_t thread_pool[THREAD_POOL_SIZE];
ClientRequest request_queue[REQUEST_QUEUE_SIZE];
int queue_start = 0, queue_end = 0, queue_count = 0;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_not_empty = PTHREAD_COND_INITIALIZER;
pthread_cond_t queue_not_full = PTHREAD_COND_INITIALIZER;

volatile sig_atomic_t server_running = 1;

void log_message(const char *level, const char *msg) {
    pthread_mutex_lock(&log_mutex);
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("[%s] [%s] %s\n", time_buf, level, msg);
    fflush(stdout);
    pthread_mutex_unlock(&log_mutex);
}

void log_error(const char *msg) {
    char error_buf[512];
    snprintf(error_buf, sizeof(error_buf), "%s: %s", msg, strerror(errno));
    log_message("ERROR", error_buf);
}

void send_error(int client_socket, int code, const char *status_msg) {
    char response[BUFFER_SIZE];
    int content_len = strlen(status_msg);
    int response_len = snprintf(response, sizeof(response),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: text/plain\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n"
             "Server: dorbs/0.1\r\n\r\n"
             "%s",
             code, status_msg, content_len, status_msg);
    
    if (response_len > 0 && (size_t)response_len < sizeof(response)) {
        send(client_socket, response, response_len, 0);
    }
    close(client_socket);
}

void url_decode(const char *src, char *dest, size_t dest_size) {
    char *p = dest;
    const char *end = dest + dest_size - 1; 
    while (*src && p < end) {
        if (*src == '%' && src[1] && src[2] && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])) {
            char hex[3] = {src[1], src[2], '\0'};
            *p++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            *p++ = ' ';
            src++;
        } else {
            *p++ = *src++;
        }
    }
    *p = '\0';
}

int is_valid_path(const char *path) {
    if (!path || path[0] != '/' || strlen(path) > MAX_PATH_LENGTH) {
        return 0;
    }

    char decoded_path[MAX_PATH_LENGTH + 1];
    url_decode(path, decoded_path, sizeof(decoded_path));

    if (strstr(decoded_path, "..")) {
        return 0;
    }

    for (size_t i = 1; decoded_path[i] != '\0'; i++) {
        if (decoded_path[i] == '/') {
            return 0;
        }
    }

    if (strlen(decoded_path) <= 1) {
        return 0;
    }

    return 1;
}

unsigned int hash_ip(const char *ip) {
    unsigned int hash = 5381;
    int c;
    while ((c = *ip++)) {
        hash = ((hash << 5) + hash) + c; // djb2 hash
    }
    return hash % RATE_LIMIT_BUCKETS;
}

int is_rate_limited(struct sockaddr_storage *client_addr) {
    char ip[INET6_ADDRSTRLEN];
    if (client_addr->ss_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)client_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    } else if (client_addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)client_addr;
        inet_ntop(AF_INET6, &addr->sin6_addr, ip, sizeof(ip));
    } else {
        return 1;
    }

    unsigned int bucket = hash_ip(ip);
    pthread_mutex_lock(&rate_limit_mutexes[bucket]);

    RateLimitEntry *entry = rate_limit_table[bucket];
    while (entry) {
        if (strcmp(entry->ip, ip) == 0) {
            time_t now = time(NULL);
            if (now - entry->window_start > RATE_LIMIT_WINDOW) {
                entry->window_start = now;
                entry->request_count = 1;
            } else {
                entry->request_count++;
                if (entry->request_count > MAX_REQUESTS_PER_IP) {
                    pthread_mutex_unlock(&rate_limit_mutexes[bucket]);
                    return 1;
                }
            }
            pthread_mutex_unlock(&rate_limit_mutexes[bucket]);
            return 0;
        }
        entry = entry->next;
    }

    entry = malloc(sizeof(RateLimitEntry));
    if (!entry) {
        pthread_mutex_unlock(&rate_limit_mutexes[bucket]);
        return 1;
    }
    strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
    entry->ip[sizeof(entry->ip) - 1] = '\0';
    entry->request_count = 1;
    entry->window_start = time(NULL);
    entry->next = rate_limit_table[bucket];
    rate_limit_table[bucket] = entry;

    pthread_mutex_unlock(&rate_limit_mutexes[bucket]);
    return 0;
}

const char *get_file_extension(const char *filename) {
    const char *dot = strrchr(filename, '.');
    return !dot || dot == filename ? "" : dot;
}

int is_allowed_file(const char *filename) {
    const char *ext = get_file_extension(filename);
    return (strcmp(ext, ".html") == 0 || strcmp(ext, ".css") == 0 || strcmp(ext, ".webp") == 0);
}

void cache_all_files() {
    DIR *dir = opendir(".");
    if (!dir) {
        log_error("Cannot open current directory");
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL && cache_count < MAX_FILES) {
        // First, perform cheap check on file extension
        if (!is_allowed_file(ent->d_name)) continue;

        struct stat file_info;
        if (stat(ent->d_name, &file_info) != 0) {
            continue;
        }

        // This ensures we only cache regular files and is portable across all POSIX systems.
        if (!S_ISREG(file_info.st_mode)) {
            continue;
        }
        
        if (file_info.st_size > MAX_FILE_SIZE || file_info.st_size == 0) continue;

        if (total_cache_memory + file_info.st_size > MAX_TOTAL_CACHE_MEMORY) {
            log_message("WARN", "Total cache memory limit reached, cannot cache more files.");
            break;
        }

        FILE *file = fopen(ent->d_name, "rb");
        if (!file) continue;

        char *file_data = malloc(file_info.st_size);
        if (!file_data) {
            fclose(file);
            log_message("CRITICAL", "Memory allocation failed for file cache. Exiting.");
            exit(EXIT_FAILURE);
        }

        if (fread(file_data, 1, file_info.st_size, file) != (size_t)file_info.st_size) {
            free(file_data);
            fclose(file);
            continue;
        }
        fclose(file);

        caches[cache_count].data = file_data;
        // CHANGED: Replaced strncpy with snprintf to prevent compiler warnings (-Wstringop-truncation)
        // and ensure guaranteed null-termination in a safer, more modern way.
        snprintf(caches[cache_count].name, sizeof(caches[cache_count].name), "%s", ent->d_name);
        caches[cache_count].size = file_info.st_size;
        caches[cache_count].last_access = time(NULL);
        
        total_cache_memory += file_info.st_size;
        
        char msg[512];
        snprintf(msg, sizeof(msg), "Cached: %s (%zu bytes)", ent->d_name, file_info.st_size);
        log_message("INFO", msg);
        
        cache_count++;
    }
    closedir(dir);
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Cached %d files, using %zu bytes (%.2f MB)", 
             cache_count, total_cache_memory, (double)total_cache_memory / (1024*1024));
    log_message("INFO", msg);
}

void cleanup_rate_limit_table() {
    time_t now = time(NULL);
    for (int i = 0; i < RATE_LIMIT_BUCKETS; i++) {
        pthread_mutex_lock(&rate_limit_mutexes[i]);
        RateLimitEntry **entry_ptr = &rate_limit_table[i];
        while (*entry_ptr) {
            if (now - (*entry_ptr)->window_start > RATE_LIMIT_WINDOW * 2) {
                RateLimitEntry *stale = *entry_ptr;
                *entry_ptr = stale->next;
                free(stale);
            } else {
                entry_ptr = &(*entry_ptr)->next;
            }
        }
        pthread_mutex_unlock(&rate_limit_mutexes[i]);
    }
}

void handle_client(ClientRequest *request) {
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(request->client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    char client_ip[INET6_ADDRSTRLEN];
    if (request->client_addr.ss_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)&request->client_addr;
        inet_ntop(AF_INET, &addr->sin_addr, client_ip, sizeof(client_ip));
    } else {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&request->client_addr;
        inet_ntop(AF_INET6, &addr->sin6_addr, client_ip, sizeof(client_ip));
    }

    if (is_rate_limited(&request->client_addr)) {
        send_error(request->client_socket, 429, "Too Many Requests");
        return;
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = recv(request->client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        close(request->client_socket);
        return;
    }
    buffer[bytes_read] = '\0';

    char method[16], path[MAX_PATH_LENGTH + 1], protocol[16];
    if (sscanf(buffer, "%15s %255s %15s", method, path, protocol) != 3) {
        send_error(request->client_socket, 400, "Bad Request");
        return;
    }

    if (strcmp(method, "GET") != 0) {
        send_error(request->client_socket, 405, "Method Not Allowed");
        return;
    }

    if (!is_valid_path(path)) {
        send_error(request->client_socket, 404, "Not Found");
        return;
    }

    char normalized_path[MAX_PATH_LENGTH + 1];
    url_decode(path + 1, normalized_path, sizeof(normalized_path));

    pthread_rwlock_rdlock(&cache_rwlock);
    FileCache *file_to_serve = NULL;
    int found_idx = -1;
    for (int i = 0; i < cache_count; i++) {
        if (strcmp(normalized_path, caches[i].name) == 0) {
            file_to_serve = &caches[i];
            found_idx = i;
            break;
        }
    }
    pthread_rwlock_unlock(&cache_rwlock);

    if (!file_to_serve) {
        send_error(request->client_socket, 404, "Not Found");
        return;
    }
    
    pthread_rwlock_wrlock(&cache_rwlock);
    if (found_idx != -1) {
        caches[found_idx].last_access = time(NULL);
    }
    pthread_rwlock_unlock(&cache_rwlock);


    const char *ext = get_file_extension(file_to_serve->name);
    const char *content_type = "text/plain";
    if (strcmp(ext, ".css") == 0) content_type = "text/css";
    else if (strcmp(ext, ".webp") == 0) content_type = "image/webp";
    else if (strcmp(ext, ".html") == 0) content_type = "text/html";

    char header[BUFFER_SIZE];
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 200 OK\r\n"
                              "Content-Type: %s\r\n"
                              "Content-Length: %zu\r\n"
                              "Connection: close\r\n"
                              "Cache-Control: public, max-age=3600\r\n"
                              "X-Content-Type-Options: nosniff\r\n"
                              "X-Frame-Options: DENY\r\n"
                              "Content-Security-Policy: default-src 'self';\r\n"
                              "Server: dorbs/0.1\r\n\r\n",
                              content_type, file_to_serve->size);

    if (header_len > 0 && (size_t)header_len < sizeof(header)) {
        send(request->client_socket, header, header_len, 0);
        send(request->client_socket, file_to_serve->data, file_to_serve->size, 0);
    }

    char msg[512];
    snprintf(msg, sizeof(msg), "200 OK - Served %s to %s", file_to_serve->name, client_ip);
    log_message("INFO", msg);

    close(request->client_socket);
}

void *thread_worker(void *arg) {
    (void)arg; // Silence unused parameter warning
    while (server_running) {
        pthread_mutex_lock(&queue_mutex);
        while (queue_count == 0 && server_running) {
            pthread_cond_wait(&queue_not_empty, &queue_mutex);
        }
        if (!server_running) {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }
        
        ClientRequest request = request_queue[queue_start];
        queue_start = (queue_start + 1) % REQUEST_QUEUE_SIZE;
        queue_count--;
        
        pthread_cond_signal(&queue_not_full);
        pthread_mutex_unlock(&queue_mutex);

        handle_client(&request);
    }
    return NULL;
}

void shutdown_server(int signo) {
    (void)signo; // Silence unused parameter warning
    server_running = 0;
    shutdown(0, SHUT_RD);
    pthread_cond_broadcast(&queue_not_empty);
    pthread_cond_broadcast(&queue_not_full);
}

void free_cache_data() {
    for (int i = 0; i < cache_count; i++) {
        if (caches[i].data) {
            free(caches[i].data);
            caches[i].data = NULL;
        }
    }
}

void free_rate_limit_table() {
    for (int i = 0; i < RATE_LIMIT_BUCKETS; i++) {
        pthread_mutex_lock(&rate_limit_mutexes[i]);
        RateLimitEntry *entry = rate_limit_table[i];
        while (entry) {
            RateLimitEntry *next = entry->next;
            free(entry);
            entry = next;
        }
        rate_limit_table[i] = NULL;
        pthread_mutex_unlock(&rate_limit_mutexes[i]);
        pthread_mutex_destroy(&rate_limit_mutexes[i]);
    }
}

int main(int argc, char *argv[]) {
    int port = (argc > 1) ? atoi(argv[1]) : DEFAULT_PORT;
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port number.\n");
        return EXIT_FAILURE;
    }

    signal(SIGINT, shutdown_server);
    signal(SIGTERM, shutdown_server);
    signal(SIGPIPE, SIG_IGN);

    log_message("INFO", "Starting adorable server");
    
    cache_all_files();
    if (cache_count == 0) {
        log_message("ERROR", "No allowed files (.html, .css, .webp) found to serve.");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < RATE_LIMIT_BUCKETS; i++) {
        pthread_mutex_init(&rate_limit_mutexes[i], NULL);
    }

    int server_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_fd < 0) {
        log_error("Socket creation failed");
        return EXIT_FAILURE;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in6 address = {0};
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_any;
    address.sin6_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        log_error("Bind failed");
        close(server_fd);
        return EXIT_FAILURE;
    }

    if (listen(server_fd, SOMAXCONN) < 0) {
        log_error("Listen failed");
        close(server_fd);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_create(&thread_pool[i], NULL, thread_worker, NULL) != 0) {
            log_error("Thread creation failed");
            server_running = 0;
            break;
        }
    }

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║                     dorbs v0.1                       ║\n");
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║ Server URL: http://[::1]:%-5d or http://localhost:%-5d║\n", port, port);
    printf("╚══════════════════════════════════════════════════════╝\n");

    long request_count_for_cleanup = 0;
    while (server_running) {
        ClientRequest request;
        socklen_t addr_len = sizeof(request.client_addr);
        request.client_socket = accept(server_fd, (struct sockaddr *)&request.client_addr, &addr_len);
        
        if (request.client_socket < 0) {
            if (server_running) log_error("Accept failed");
            continue;
        }

        if (++request_count_for_cleanup % CLEANUP_INTERVAL == 0) {
            cleanup_rate_limit_table();
        }

        pthread_mutex_lock(&queue_mutex);
        while (queue_count >= REQUEST_QUEUE_SIZE && server_running) {
            pthread_cond_wait(&queue_not_full, &queue_mutex);
        }
        if (!server_running) {
            close(request.client_socket);
            pthread_mutex_unlock(&queue_mutex);
            break;
        }
        
        request_queue[queue_end] = request;
        queue_end = (queue_end + 1) % REQUEST_QUEUE_SIZE;
        queue_count++;
        
        pthread_cond_signal(&queue_not_empty);
        pthread_mutex_unlock(&queue_mutex);
    }

    log_message("INFO", "Shutting down server...");
    
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_join(thread_pool[i], NULL);
    }
    
    close(server_fd);
    free_cache_data();
    free_rate_limit_table();
    log_message("INFO", "Server shutdown complete");
    
    return 0;
}