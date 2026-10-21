#define _POSIX_C_SOURCE 200809L

/*
 * Small LAN-only HTTP control page + UDP discovery/messaging demo.
 * Build: cc -std=c11 -Wall -Wextra -O2 lan_server.c -pthread -o lan_server
 * Run:   ./lan_server
 * Open:  http://127.0.0.1:8088
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define HTTP_PORT 8088
#define UDP_LISTEN_PORT 8888
#define UDP_CLIENT_PORT 8889
#define HTTP_BUF_SIZE 16384
#define HTTP_BODY_MAX 8192
#define USERNAME_MAX 128
#define IP_TEXT_MAX INET_ADDRSTRLEN
#define MESSAGE_MAX 400
#define PEER_MAX 64
#define INBOX_MAX 20

#define DISCOVER_TEXT "LANCHAT/1 DISCOVER"
#define HERE_PREFIX   "LANCHAT/1 HERE "
#define MSG_PREFIX    "LANCHAT/1 MSG "

struct Peer {
    char name[USERNAME_MAX];
    char ip[IP_TEXT_MAX];
    time_t seen;
};

struct InboxItem {
    char name[USERNAME_MAX];
    char ip[IP_TEXT_MAX];
    char message[MESSAGE_MAX + 1];
    time_t received;
};

static char g_username[USERNAME_MAX] = "unknown";
static int g_udp_client_fd = -1; /* Bound to UDP/8889; sends and receives replies. */
static atomic_int g_listener_enabled = 1;
static pthread_mutex_t g_data_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct Peer g_peers[PEER_MAX];
static size_t g_peer_count = 0;
static struct InboxItem g_inbox[INBOX_MAX];
static size_t g_inbox_count = 0;

static void sleep_ms(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static int send_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static void http_reply(int fd, const char *status, const char *content_type,
                       const char *body) {
    char header[1024];
    size_t body_len = strlen(body);
    int n = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "Content-Security-Policy: default-src 'self' 'unsafe-inline'; connect-src 'self'\r\n"
        "\r\n",
        status, content_type, body_len);
    if (n > 0 && (size_t)n < sizeof(header)) {
        (void)send_all(fd, header, (size_t)n);
        (void)send_all(fd, body, body_len);
    }
}

static void appendf(char *out, size_t cap, size_t *used, const char *fmt, ...) {
    if (*used >= cap) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + *used, cap - *used, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= cap - *used) *used = cap - 1;
    else *used += (size_t)n;
}

static void append_json_string(char *out, size_t cap, size_t *used, const char *s) {
    appendf(out, cap, used, "\"");
    for (const unsigned char *p = (const unsigned char *)s; *p && *used < cap - 1; ++p) {
        switch (*p) {
            case '"': appendf(out, cap, used, "\\\""); break;
            case '\\': appendf(out, cap, used, "\\\\"); break;
            case '\b': appendf(out, cap, used, "\\b"); break;
            case '\f': appendf(out, cap, used, "\\f"); break;
            case '\n': appendf(out, cap, used, "\\n"); break;
            case '\r': appendf(out, cap, used, "\\r"); break;
            case '\t': appendf(out, cap, used, "\\t"); break;
            default:
                if (*p < 0x20) appendf(out, cap, used, "\\u%04x", (unsigned)*p);
                else appendf(out, cap, used, "%c", *p);
        }
    }
    appendf(out, cap, used, "\"");
}

/* True only for private, link-local, or loopback IPv4 addresses. */
static int is_lan_ipv4(struct in_addr addr) {
    uint32_t ip = ntohl(addr.s_addr);
    if ((ip & 0xff000000U) == 0x0a000000U) return 1;       /* 10/8 */
    if ((ip & 0xfff00000U) == 0xac100000U) return 1;       /* 172.16/12 */
    if ((ip & 0xffff0000U) == 0xc0a80000U) return 1;       /* 192.168/16 */
    if ((ip & 0xffff0000U) == 0xa9fe0000U) return 1;       /* 169.254/16 */
    if ((ip & 0xff000000U) == 0x7f000000U) return 1;       /* 127/8 */
    return 0;
}

static int url_decode(const char *src, char *dst, size_t cap) {
    size_t j = 0;
    for (size_t i = 0; src[i]; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c == '+') c = ' ';
        else if (c == '%') {
            if (!src[i + 1] || !src[i + 2]) return -1;
            int hi, lo;
            char a = src[++i], b = src[++i];
            hi = isdigit((unsigned char)a) ? a - '0' :
                 (tolower((unsigned char)a) >= 'a' && tolower((unsigned char)a) <= 'f' ?
                  tolower((unsigned char)a) - 'a' + 10 : -1);
            lo = isdigit((unsigned char)b) ? b - '0' :
                 (tolower((unsigned char)b) >= 'a' && tolower((unsigned char)b) <= 'f' ?
                  tolower((unsigned char)b) - 'a' + 10 : -1);
            if (hi < 0 || lo < 0) return -1;
            c = (unsigned char)((hi << 4) | lo);
            if (c == '\0') return -1;
        }
        if (j + 1 >= cap) return -1;
        dst[j++] = (char)c;
    }
    dst[j] = '\0';
    return 0;
}

static int form_value(const char *body, const char *wanted,
                      char *out, size_t out_cap) {
    const char *p = body;
    while (*p) {
        const char *end = strchr(p, '&');
        if (!end) end = p + strlen(p);
        const char *eq = memchr(p, '=', (size_t)(end - p));
        if (eq) {
            char key[128];
            size_t key_len = (size_t)(eq - p);
            if (key_len < sizeof(key)) {
                char raw_key[128];
                memcpy(raw_key, p, key_len);
                raw_key[key_len] = '\0';
                if (url_decode(raw_key, key, sizeof(key)) == 0 && strcmp(key, wanted) == 0) {
                    size_t val_len = (size_t)(end - eq - 1);
                    char *raw_val = malloc(val_len + 1);
                    if (!raw_val) return -1;
                    memcpy(raw_val, eq + 1, val_len);
                    raw_val[val_len] = '\0';
                    int result = url_decode(raw_val, out, out_cap);
                    free(raw_val);
                    return result;
                }
            }
        }
        p = *end ? end + 1 : end;
    }
    return -1;
}

static void url_encode(const char *src, char *dst, size_t cap) {
    static const char hex[] = "0123456789ABCDEF";
    size_t j = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p; ++p) {
        unsigned char c = *p;
        int safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                   c == '.' || c == '~';
        if (safe) {
            if (j + 1 >= cap) break;
            dst[j++] = (char)c;
        } else {
            if (j + 3 >= cap) break;
            dst[j++] = '%';
            dst[j++] = hex[c >> 4];
            dst[j++] = hex[c & 15];
        }
    }
    dst[j] = '\0';
}

static void add_peer(const char *name, const char *ip) {
    time_t now = time(NULL);
    pthread_mutex_lock(&g_data_mutex);
    for (size_t i = 0; i < g_peer_count; ++i) {
        if (strcmp(g_peers[i].ip, ip) == 0) {
            snprintf(g_peers[i].name, sizeof(g_peers[i].name), "%s", name);
            g_peers[i].seen = now;
            pthread_mutex_unlock(&g_data_mutex);
            return;
        }
    }
    if (g_peer_count == PEER_MAX) {
        memmove(&g_peers[0], &g_peers[1], sizeof(g_peers[0]) * (PEER_MAX - 1));
        g_peer_count--;
    }
    snprintf(g_peers[g_peer_count].name, sizeof(g_peers[g_peer_count].name), "%s", name);
    snprintf(g_peers[g_peer_count].ip, sizeof(g_peers[g_peer_count].ip), "%s", ip);
    g_peers[g_peer_count].seen = now;
    g_peer_count++;
    pthread_mutex_unlock(&g_data_mutex);
}

static void add_inbox_item(const char *name, const char *ip, const char *message) {
    pthread_mutex_lock(&g_data_mutex);
    if (g_inbox_count == INBOX_MAX) {
        memmove(&g_inbox[0], &g_inbox[1], sizeof(g_inbox[0]) * (INBOX_MAX - 1));
        g_inbox_count--;
    }
    struct InboxItem *item = &g_inbox[g_inbox_count++];
    snprintf(item->name, sizeof(item->name), "%s", name);
    snprintf(item->ip, sizeof(item->ip), "%s", ip);
    snprintf(item->message, sizeof(item->message), "%s", message);
    item->received = time(NULL);
    pthread_mutex_unlock(&g_data_mutex);
}

static void addr_to_text(struct in_addr addr, char out[IP_TEXT_MAX]) {
    if (!inet_ntop(AF_INET, &addr, out, IP_TEXT_MAX))
        snprintf(out, IP_TEXT_MAX, "0.0.0.0");
}

static int open_listener_socket(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(UDP_LISTEN_PORT);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind UDP 8888");
        close(fd);
        return -1;
    }
    fprintf(stderr, "UDP listener active on port %d\n", UDP_LISTEN_PORT);
    return fd;
}

static void process_udp_request(int fd, char *buf, struct sockaddr_in *from) {
    char ip[IP_TEXT_MAX];
    addr_to_text(from->sin_addr, ip);
    if (!is_lan_ipv4(from->sin_addr)) return;

    if (strcmp(buf, DISCOVER_TEXT) == 0) {
        char encoded_name[USERNAME_MAX * 3];
        char reply[USERNAME_MAX * 3 + 64];
        url_encode(g_username, encoded_name, sizeof(encoded_name));
        snprintf(reply, sizeof(reply), "%s%s", HERE_PREFIX, encoded_name);
        (void)sendto(fd, reply, strlen(reply), 0,
                     (struct sockaddr *)from, sizeof(*from));
        return;
    }

    if (strncmp(buf, MSG_PREFIX, strlen(MSG_PREFIX)) == 0) {
        char *encoded_name = buf + strlen(MSG_PREFIX);
        char *space = strchr(encoded_name, ' ');
        if (!space) return;
        *space++ = '\0';
        char name[USERNAME_MAX];
        char message[MESSAGE_MAX + 1];
        if (url_decode(encoded_name, name, sizeof(name)) != 0 ||
            url_decode(space, message, sizeof(message)) != 0) return;
        add_inbox_item(name, ip, message);
        fprintf(stderr, "Message from %s (%s)\n", name, ip);
    }
}

static void *udp_listener_thread(void *unused) {
    (void)unused;
    int fd = -1;
    for (;;) {
        if (!atomic_load(&g_listener_enabled)) {
            if (fd >= 0) { close(fd); fd = -1; fprintf(stderr, "UDP listener disabled\n"); }
            sleep_ms(100);
            continue;
        }
        if (fd < 0) {
            fd = open_listener_socket();
            if (fd < 0) { sleep_ms(1000); continue; }
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = { .tv_sec = 0, .tv_usec = 250000 };
        int ready = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("select UDP 8888");
            close(fd); fd = -1;
            continue;
        }
        if (ready == 0) continue;

        char buf[2048];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&from, &from_len);
        if (n <= 0) continue;
        buf[n] = '\0';
        if (!atomic_load(&g_listener_enabled)) continue;
        process_udp_request(fd, buf, &from);
    }
    return NULL;
}

static void *udp_reply_receiver_thread(void *unused) {
    (void)unused;
    for (;;) {
        char buf[2048];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(g_udp_client_fd, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom UDP 8889");
            sleep_ms(100);
            continue;
        }
        buf[n] = '\0';
        if (!is_lan_ipv4(from.sin_addr)) continue;
        if (strncmp(buf, HERE_PREFIX, strlen(HERE_PREFIX)) == 0) {
            char name[USERNAME_MAX];
            if (url_decode(buf + strlen(HERE_PREFIX), name, sizeof(name)) != 0) continue;
            char ip[IP_TEXT_MAX];
            addr_to_text(from.sin_addr, ip);
            add_peer(name, ip);
            fprintf(stderr, "Discovered %s at %s\n", name, ip);
        }
    }
    return NULL;
}

static int send_discovery_broadcast(void) {
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(UDP_LISTEN_PORT);
    dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    ssize_t n = sendto(g_udp_client_fd, DISCOVER_TEXT, strlen(DISCOVER_TEXT), 0,
                       (struct sockaddr *)&dst, sizeof(dst));
    return n == (ssize_t)strlen(DISCOVER_TEXT) ? 0 : -1;
}

static int send_peer_message(const char *ip, const char *message) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1 || !is_lan_ipv4(addr)) return -1;
    if (strlen(message) == 0 || strlen(message) > MESSAGE_MAX) return -2;

    char enc_name[USERNAME_MAX * 3];
    char enc_message[MESSAGE_MAX * 3 + 1];
    char packet[USERNAME_MAX * 3 + MESSAGE_MAX * 3 + 64];
    url_encode(g_username, enc_name, sizeof(enc_name));
    url_encode(message, enc_message, sizeof(enc_message));
    int len = snprintf(packet, sizeof(packet), "%s%s %s", MSG_PREFIX, enc_name, enc_message);
    if (len < 0 || (size_t)len >= sizeof(packet)) return -2;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(UDP_LISTEN_PORT);
    dst.sin_addr = addr;
    ssize_t n = sendto(g_udp_client_fd, packet, (size_t)len, 0,
                       (struct sockaddr *)&dst, sizeof(dst));
    return n == len ? 0 : -1;
}

static void build_state_json(char *out, size_t cap) {
    size_t used = 0;
    appendf(out, cap, &used, "{\"enabled\":%s,\"username\":",
            atomic_load(&g_listener_enabled) ? "true" : "false");
    append_json_string(out, cap, &used, g_username);
    appendf(out, cap, &used, ",\"peers\":[");

    pthread_mutex_lock(&g_data_mutex);
    for (size_t i = 0; i < g_peer_count; ++i) {
        if (i) appendf(out, cap, &used, ",");
        appendf(out, cap, &used, "{\"name\":");
        append_json_string(out, cap, &used, g_peers[i].name);
        appendf(out, cap, &used, ",\"ip\":");
        append_json_string(out, cap, &used, g_peers[i].ip);
        appendf(out, cap, &used, ",\"seen\":%lld}", (long long)g_peers[i].seen);
    }
    appendf(out, cap, &used, "],\"inbox\":[");
    for (size_t i = 0; i < g_inbox_count; ++i) {
        if (i) appendf(out, cap, &used, ",");
        appendf(out, cap, &used, "{\"name\":");
        append_json_string(out, cap, &used, g_inbox[i].name);
        appendf(out, cap, &used, ",\"ip\":");
        append_json_string(out, cap, &used, g_inbox[i].ip);
        appendf(out, cap, &used, ",\"message\":");
        append_json_string(out, cap, &used, g_inbox[i].message);
        appendf(out, cap, &used, ",\"received\":%lld}", (long long)g_inbox[i].received);
    }
    pthread_mutex_unlock(&g_data_mutex);
    appendf(out, cap, &used, "]}");
}

static const char HTML_PAGE[] =
"<!doctype html><html><head><meta charset='utf-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>LAN Messenger</title><style>"
"body{font:16px system-ui,sans-serif;max-width:850px;margin:32px auto;padding:0 16px;color:#17202a}"
"h1{margin-bottom:4px} .muted{color:#566573} section{border:1px solid #ccd1d1;border-radius:12px;padding:16px;margin:16px 0}"
"button{padding:9px 13px;cursor:pointer}input,textarea{font:inherit;padding:8px;max-width:100%;box-sizing:border-box}"
"label{display:block;margin:10px 0 4px}textarea{width:100%;min-height:85px}#status{font-weight:600}"
"li{margin:7px 0;overflow-wrap:anywhere}.peer{display:flex;gap:10px;align-items:center;flex-wrap:wrap}"
".msg{border-bottom:1px solid #eee;padding:8px 0;white-space:pre-wrap;overflow-wrap:anywhere}</style></head><body>"
"<h1>LAN Messenger</h1><p class='muted'>Discovery and messaging for devices on the same local network.</p>"
"<section><h2>Listening</h2><label><input id='enabled' type='checkbox'> Enable incoming UDP requests on port 8888</label>"
"<p id='status' role='status'>Loading…</p><button id='discover'>Broadcast discovery from UDP 8889</button>"
"<p class='muted'>Discovery replies return the remote computer's username; its LAN IP is read from the UDP reply address.</p></section>"
"<section><h2>Discovered computers</h2><p class='muted'>Click a computer to use its IP in the send form.</p><ul id='peers'></ul></section>"
"<section><h2>Send a message</h2><form id='sendform'><label for='ip'>Recipient LAN IPv4 address</label>"
"<input id='ip' name='ip' required placeholder='e.g. 192.168.1.25' pattern='[0-9.]{7,15}'>"
"<label for='message'>Message (up to 400 characters)</label><textarea id='message' name='message' maxlength='400' required></textarea>"
"<button type='submit'>Send message</button></form><p id='sendstatus' role='status'></p></section>"
"<section><h2>Incoming messages</h2><div id='inbox' aria-live='polite'></div></section>"
"<script>"
"const $=id=>document.getElementById(id);let toggleUpdating=false;"
"async function post(path,data=''){return fetch(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:data});}"
"function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}"
"async function refresh(){try{const r=await fetch('/api/state',{cache:'no-store'});const s=await r.json();"
"if(!toggleUpdating)$('enabled').checked=s.enabled;$('status').textContent=s.enabled?'Listening on UDP port 8888':'Listener disabled (UDP port 8888 is closed)';"
"const peers=$('peers');peers.replaceChildren();if(!s.peers.length)peers.append(el('li','No computers found yet. Click the broadcast button.'));"
"for(const p of s.peers){const li=el('li');const row=el('div',undefined,'peer');const name=el('strong',p.name);const ip=el('span',p.ip);const b=el('button','Use this IP');b.type='button';b.onclick=()=>{$('ip').value=p.ip;$('message').focus();};row.append(name,ip,b);li.append(row);peers.append(li);}"
"const inbox=$('inbox');inbox.replaceChildren();if(!s.inbox.length)inbox.append(el('p','No messages received yet.','muted'));"
"for(const m of [...s.inbox].reverse()){const d=el('div',undefined,'msg');const title=el('strong',`${m.name} (${m.ip}) · ${new Date(m.received*1000).toLocaleTimeString()}`);const body=el('div',m.message);d.append(title,body);inbox.append(d);}"
"}catch(e){$('status').textContent='Could not load server state.';}}"
"$('enabled').addEventListener('change',async()=>{toggleUpdating=true;try{await post('/api/toggle','enabled='+($('enabled').checked?'1':'0'));}finally{toggleUpdating=false;refresh();}});"
"$('discover').addEventListener('click',async()=>{const b=$('discover');b.disabled=true;try{await post('/api/discover');$('status').textContent='Broadcast sent; waiting for replies…';setTimeout(refresh,900);}catch(e){$('status').textContent='Broadcast failed.';}finally{setTimeout(()=>b.disabled=false,500);}});"
"$('sendform').addEventListener('submit',async e=>{e.preventDefault();$('sendstatus').textContent='Sending…';const body=new URLSearchParams({ip:$('ip').value.trim(),message:$('message').value});"
"try{const r=await post('/api/send',body.toString());const t=await r.text();if(!r.ok)throw new Error(t);$('sendstatus').textContent='Message sent to '+$('ip').value.trim()+'.';$('message').value='';}catch(err){$('sendstatus').textContent='Send failed: '+err.message;}});"
"refresh();setInterval(refresh,2000);</script></body></html>";

static int copy_header_value(const char *line, size_t len, const char *prefix,
                             char *out, size_t out_cap) {
    size_t prefix_len = strlen(prefix);
    if (len < prefix_len || strncasecmp(line, prefix, prefix_len) != 0) return 0;
    const char *p = line + prefix_len;
    const char *end = line + len;
    while (p < end && (*p == ' ' || *p == '\t')) ++p;
    while (end > p && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) --end;
    size_t n = (size_t)(end - p);
    if (n >= out_cap) return -1;
    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

static int valid_local_host(const char *host) {
    return strcmp(host, "127.0.0.1:8088") == 0 || strcmp(host, "localhost:8088") == 0;
}

static int valid_local_origin(const char *origin) {
    return strcmp(origin, "http://127.0.0.1:8088") == 0 ||
           strcmp(origin, "http://localhost:8088") == 0;
}

static void handle_http_client(int client_fd) {
    char req[HTTP_BUF_SIZE];
    char host[256] = "";
    char origin[256] = "";
    size_t used = 0, header_len = 0, content_len = 0;
    int header_found = 0;

    while (used < sizeof(req) - 1) {
        ssize_t n = recv(client_fd, req + used, sizeof(req) - 1 - used, 0);
        if (n < 0) { if (errno == EINTR) continue; return; }
        if (n == 0) return;
        used += (size_t)n;
        req[used] = '\0';

        if (!header_found) {
            char *end = strstr(req, "\r\n\r\n");
            if (end) {
                header_found = 1;
                header_len = (size_t)(end - req) + 4;
                char *line_end = strstr(req, "\r\n");
                if (!line_end) return;
                *line_end = '\0';
                char method[16], path[256];
                if (sscanf(req, "%15s %255s", method, path) != 2) {
                    http_reply(client_fd, "400 Bad Request", "text/plain", "Bad request");
                    return;
                }
                /* Restore request line CRLF; route is parsed again below. */
                *line_end = '\r';
                char *line = line_end + 2;
                while (line < end) {
                    char *next = strstr(line, "\r\n");
                    if (!next || next == line) break;
                    size_t line_len = (size_t)(next - line);
                    (void)copy_header_value(line, line_len, "Host:", host, sizeof(host));
                    (void)copy_header_value(line, line_len, "Origin:", origin, sizeof(origin));
                    if (strncasecmp(line, "Content-Length:", 15) == 0) {
                        char *v = line + 15;
                        while (*v == ' ' || *v == '\t') ++v;
                        char *num_end = NULL;
                        unsigned long parsed = strtoul(v, &num_end, 10);
                        if (num_end == v || (*num_end && *num_end != '\r') || parsed > HTTP_BODY_MAX) {
                            http_reply(client_fd, "413 Content Too Large", "text/plain", "Body too large");
                            return;
                        }
                        content_len = (size_t)parsed;
                    }
                    line = next + 2;
                }
            }
        }
        if (header_found && used >= header_len + content_len) break;
    }

    if (!header_found || used < header_len + content_len) {
        http_reply(client_fd, "400 Bad Request", "text/plain", "Incomplete request");
        return;
    }

    char method[16] = {0}, path[256] = {0};
    if (sscanf(req, "%15s %255s", method, path) != 2) {
        http_reply(client_fd, "400 Bad Request", "text/plain", "Bad request");
        return;
    }
    char *query = strchr(path, '?');
    if (query) *query = '\0';
    char *body = req + header_len;
    body[content_len] = '\0';

    /* Prevent Host-header/DNS-rebinding tricks and cross-origin localhost POSTs. */
    if (!valid_local_host(host)) {
        http_reply(client_fd, "403 Forbidden", "text/plain", "Only localhost is accepted");
        return;
    }
    if (strcmp(method, "POST") == 0 && strncmp(path, "/api/", 5) == 0 &&
        !valid_local_origin(origin)) {
        http_reply(client_fd, "403 Forbidden", "text/plain", "Cross-origin requests are not allowed");
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/") == 0) {
        http_reply(client_fd, "200 OK", "text/html", HTML_PAGE);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/state") == 0) {
        char json[40000];
        build_state_json(json, sizeof(json));
        http_reply(client_fd, "200 OK", "application/json", json);
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/toggle") == 0) {
        char value[16];
        if (form_value(body, "enabled", value, sizeof(value)) != 0 ||
            (strcmp(value, "0") != 0 && strcmp(value, "1") != 0)) {
            http_reply(client_fd, "400 Bad Request", "text/plain", "Expected enabled=0 or enabled=1");
        } else {
            atomic_store(&g_listener_enabled, strcmp(value, "1") == 0);
            http_reply(client_fd, "200 OK", "application/json", "{\"ok\":true}");
        }
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/discover") == 0) {
        if (send_discovery_broadcast() == 0)
            http_reply(client_fd, "200 OK", "application/json", "{\"ok\":true}");
        else
            http_reply(client_fd, "500 Internal Server Error", "text/plain", "Broadcast send failed");
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/send") == 0) {
        char ip[64], message[MESSAGE_MAX + 1];
        if (form_value(body, "ip", ip, sizeof(ip)) != 0 ||
            form_value(body, "message", message, sizeof(message)) != 0) {
            http_reply(client_fd, "400 Bad Request", "text/plain", "Missing IP or message");
        } else {
            int result = send_peer_message(ip, message);
            if (result == 0) http_reply(client_fd, "200 OK", "application/json", "{\"ok\":true}");
            else if (result == -2) http_reply(client_fd, "400 Bad Request", "text/plain", "Message must be 1-400 characters");
            else http_reply(client_fd, "400 Bad Request", "text/plain", "Use a private/local IPv4 address and check that the recipient is listening on UDP 8888");
        }
    } else {
        http_reply(client_fd, "404 Not Found", "text/plain", "Not found");
    }
}

static int open_http_listener(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(HTTP_PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) { close(fd); return -1; }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind HTTP 127.0.0.1:8088");
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) { perror("listen HTTP"); close(fd); return -1; }
    return fd;
}

int main(void) {
    struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_name && pw->pw_name[0])
        snprintf(g_username, sizeof(g_username), "%s", pw->pw_name);
    else if (getenv("USER"))
        snprintf(g_username, sizeof(g_username), "%s", getenv("USER"));

    g_udp_client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp_client_fd < 0) { perror("socket UDP client"); return 1; }
    int yes = 1;
    if (setsockopt(g_udp_client_fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes)) < 0) {
        perror("setsockopt SO_BROADCAST"); close(g_udp_client_fd); return 1;
    }
    (void)setsockopt(g_udp_client_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    client_addr.sin_port = htons(UDP_CLIENT_PORT);
    if (bind(g_udp_client_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("bind UDP client port 8889");
        close(g_udp_client_fd);
        return 1;
    }

    pthread_t listener_thread, receiver_thread;
    if (pthread_create(&listener_thread, NULL, udp_listener_thread, NULL) != 0) {
        fprintf(stderr, "Could not create UDP listener thread\n"); close(g_udp_client_fd); return 1;
    }
    if (pthread_create(&receiver_thread, NULL, udp_reply_receiver_thread, NULL) != 0) {
        fprintf(stderr, "Could not create UDP reply receiver thread\n"); close(g_udp_client_fd); return 1;
    }
    (void)pthread_detach(listener_thread);
    (void)pthread_detach(receiver_thread);

    int http_fd = open_http_listener();
    if (http_fd < 0) { close(g_udp_client_fd); return 1; }
    fprintf(stderr, "LAN Messenger running as '%s'\n", g_username);
    fprintf(stderr, "Open http://127.0.0.1:%d in this computer's browser\n", HTTP_PORT);
    fprintf(stderr, "UDP discovery/messages use port %d; replies originate from port %d\n",
            UDP_LISTEN_PORT, UDP_CLIENT_PORT);

    for (;;) {
        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);
        int fd = accept(http_fd, (struct sockaddr *)&client, &client_len);
        if (fd < 0) {
            if (errno == EINTR) continue;
            perror("accept HTTP");
            continue;
        }
        handle_http_client(fd);
        close(fd);
    }
    /* Unreachable in this minimal example. */
    close(http_fd);
    close(g_udp_client_fd);
    return 0;
}

