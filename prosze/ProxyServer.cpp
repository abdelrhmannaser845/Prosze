#include "ProxyServer.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cctype>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

namespace {
#ifdef _WIN32
using Socket = SOCKET;
constexpr Socket invalid_socket = INVALID_SOCKET;
void close_socket(Socket s) { closesocket(s); }
#else
using Socket = int;
constexpr Socket invalid_socket = -1;
void close_socket(Socket s) { close(s); }
#endif

void set_socket_timeout(Socket socket, unsigned seconds)
{
#ifdef _WIN32
    DWORD milliseconds = seconds * 1000;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&milliseconds), sizeof(milliseconds));
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&milliseconds), sizeof(milliseconds));
#else
    timeval timeout{ static_cast<long>(seconds), 0 };
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif
}

struct Url { std::string host, port, prefix; };

std::string lower_copy(std::string value)
{
    for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

std::string trim_copy(const std::string& value)
{
    size_t first = 0, last = value.size();
    while (first < last && std::isspace(static_cast<unsigned char>(value[first]))) ++first;
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1]))) --last;
    return value.substr(first, last - first);
}

bool parse_url(const std::string& raw, Url& url)
{
    const std::string scheme = "http://";
    if (raw.compare(0, scheme.size(), scheme) != 0) return false;
    std::string rest = raw.substr(scheme.size());
    size_t slash = rest.find('/');
    std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    url.prefix = slash == std::string::npos ? "" : rest.substr(slash);
    size_t colon = authority.rfind(':');
    if (authority.empty()) return false;
    if (colon != std::string::npos) {
        url.host = authority.substr(0, colon);
        url.port = authority.substr(colon + 1);
    } else { url.host = authority; url.port = "80"; }
    if (url.host.empty() || url.port.empty()) return false;
    for (char c : url.port) if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    return true;
}

bool send_all(Socket socket, const std::string& data)
{
    size_t offset = 0;
    while (offset < data.size()) {
        int n = send(socket, data.data() + offset,
                     static_cast<int>(std::min<size_t>(data.size() - offset, 1 << 20)), 0);
        if (n <= 0) return false;
        offset += static_cast<size_t>(n);
    }
    return true;
}

bool receive_until(Socket socket, std::string& data, const std::string& marker, size_t limit)
{
    char buffer[8192];
    while (data.find(marker) == std::string::npos) {
        int n = recv(socket, buffer, sizeof(buffer), 0);
        if (n <= 0 || data.size() + static_cast<size_t>(n) > limit) return false;
        data.append(buffer, static_cast<size_t>(n));
    }
    return true;
}

Socket connect_upstream(const Url& url)
{
    addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    addrinfo* result = nullptr;
    if (getaddrinfo(url.host.c_str(), url.port.c_str(), &hints, &result) != 0) return invalid_socket;
    Socket connected = invalid_socket;
    for (addrinfo* item = result; item; item = item->ai_next) {
        Socket candidate = static_cast<Socket>(socket(item->ai_family, item->ai_socktype, item->ai_protocol));
        if (candidate == invalid_socket) continue;
        if (connect(candidate, item->ai_addr, static_cast<int>(item->ai_addrlen)) == 0) { connected = candidate; break; }
        close_socket(candidate);
    }
    freeaddrinfo(result);
    return connected;
}

bool hop_header(const std::string& name)
{
    const std::string n = lower_copy(name);
    return n == "host" || n == "content-length" || n == "connection" ||
           n == "keep-alive" || n == "transfer-encoding" || n == "proxy-connection" ||
           n == "te" || n == "upgrade" || n == "accept-encoding";
}

std::string header_value(const std::vector<std::pair<std::string, std::string>>& headers,
                         const std::string& name)
{
    for (const auto& header : headers) if (lower_copy(header.first) == name) return header.second;
    return {};
}

bool parse_request(const std::string& raw, std::string& request_line,
                   std::vector<std::pair<std::string, std::string>>& headers,
                   std::string& body, size_t& content_length)
{
    size_t split = raw.find("\r\n\r\n");
    if (split == std::string::npos) return false;
    std::istringstream stream(raw.substr(0, split));
    if (!std::getline(stream, request_line)) return false;
    if (!request_line.empty() && request_line.back() == '\r') request_line.pop_back();
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon == std::string::npos) return false;
        headers.emplace_back(trim_copy(line.substr(0, colon)), trim_copy(line.substr(colon + 1)));
    }
    body = raw.substr(split + 4);
    size_t length = 0; bool has_length = false;
    for (const auto& header : headers) {
        std::string name = lower_copy(header.first);
        if (name == "transfer-encoding") return false;
        if (name == "content-length") {
            if (has_length) return false;
            try { length = static_cast<size_t>(std::stoull(header.second)); } catch (...) { return false; }
            has_length = true;
        }
    }
    if (length > 16 * 1024 * 1024) return false;
    content_length = length;
    if (body.size() > length) body.resize(length);
    return true;
}

bool receive_exact(Socket socket, std::string& body, size_t length)
{
    char buffer[8192];
    while (body.size() < length) {
        int n = recv(socket, buffer, static_cast<int>(std::min<size_t>(sizeof(buffer), length - body.size())), 0);
        if (n <= 0) return false;
        body.append(buffer, static_cast<size_t>(n));
    }
    body.resize(length);
    return true;
}

std::string restore_json_strings(const std::string& input, const ProszeProxyTransform& restore)
{
    if (!restore) return input;
    auto unescape = [](const std::string& raw) {
        std::string out;
        for (size_t i = 0; i < raw.size(); ++i) {
            if (raw[i] != '\\' || i + 1 >= raw.size()) { out += raw[i]; continue; }
            char escaped = raw[++i];
            switch (escaped) {
            case '"': out += '"'; break; case '\\': out += '\\'; break; case '/': out += '/'; break;
            case 'b': out += '\b'; break; case 'f': out += '\f'; break; case 'n': out += '\n'; break;
            case 'r': out += '\r'; break; case 't': out += '\t'; break;
            default: out += '\\'; out += escaped; break;
            }
        }
        return out;
    };
    auto escape = [](const std::string& raw) {
        std::string out;
        for (char c : raw) {
            switch (c) {
            case '"': out += "\\\""; break; case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break; case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break; case '\r': out += "\\r"; break; case '\t': out += "\\t"; break;
            default: out += c; break;
            }
        }
        return out;
    };
    // Rebuild token-by-token so unchanged JSON stays byte-for-byte identical.
    std::string output; size_t cursor = 0, start = 0; bool in_string = false, escaped = false;
    for (size_t i = 0; i < input.size(); ++i) {
        if (!in_string && input[i] == '"') { in_string = true; start = i + 1; continue; }
        if (!in_string) continue;
        if (escaped) { escaped = false; continue; }
        if (input[i] == '\\') { escaped = true; continue; }
        if (input[i] == '"') {
            output.append(input, cursor, start - cursor);
            std::string decoded = unescape(input.substr(start, i - start));
            std::string restored = restore(decoded);
            output += escape(restored);
            output += '"';
            cursor = i + 1; in_string = false;
        }
    }
    output.append(input, cursor, std::string::npos);
    return output;
}

std::string read_response(Socket socket, const std::string& header_block,
                          const std::vector<std::pair<std::string, std::string>>& headers,
                          size_t initial_body_size)
{
    std::string body = header_block.substr(header_block.find("\r\n\r\n") + 4);
    body.resize(std::min(body.size(), initial_body_size));
    std::string transfer = lower_copy(header_value(headers, "transfer-encoding"));
    std::string length_text = header_value(headers, "content-length");
    if (!length_text.empty()) {
        size_t expected = 0;
        try { expected = static_cast<size_t>(std::stoull(length_text)); } catch (...) { return {}; }
        if (expected > 16 * 1024 * 1024) return {};
        char buffer[8192];
        while (body.size() < expected) {
            int n = recv(socket, buffer, static_cast<int>(std::min<size_t>(sizeof(buffer), expected - body.size())), 0);
            if (n <= 0) return {};
            body.append(buffer, static_cast<size_t>(n));
        }
        body.resize(expected); return body;
    }
    char buffer[8192];
    for (;;) {
        int n = recv(socket, buffer, sizeof(buffer), 0);
        if (n <= 0) break;
        if (body.size() + static_cast<size_t>(n) > 16 * 1024 * 1024) return {};
        body.append(buffer, static_cast<size_t>(n));
    }
    if (transfer == "chunked") {
        std::string decoded;
        size_t cursor = 0;
        while (cursor < body.size()) {
            size_t line_end = body.find("\r\n", cursor);
            if (line_end == std::string::npos) return {};
            size_t size = 0;
            try { size = std::stoull(body.substr(cursor, line_end - cursor), nullptr, 16); }
            catch (...) { return {}; }
            cursor = line_end + 2;
            if (size == 0) return decoded;
            if (size > 16 * 1024 * 1024 - decoded.size() || cursor + size + 2 > body.size()) return {};
            decoded.append(body, cursor, size);
            cursor += size;
            if (body.compare(cursor, 2, "\r\n") != 0) return {};
            cursor += 2;
        }
        return {};
    }
    return body;
}

bool send_chunk(Socket socket, const std::string& data)
{
    if (data.empty()) return true;
    std::ostringstream chunk;
    chunk << std::hex << data.size() << "\r\n" << data << "\r\n";
    return send_all(socket, chunk.str());
}

bool stream_sse(Socket upstream, Socket client, const std::string& status_line,
                const std::vector<std::pair<std::string, std::string>>& headers,
                const std::string& initial, const ProszeProxyTransform& restore)
{
    std::ostringstream response;
    response << status_line << "\r\n";
    for (const auto& header : headers) {
        std::string name = lower_copy(header.first);
        if (name == "content-length" || name == "transfer-encoding" || name == "connection" ||
            name == "content-encoding") continue;
        response << header.first << ": " << header.second << "\r\n";
    }
    response << "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    if (!send_all(client, response.str())) return false;

    std::string pending;
    size_t remaining = 0;
    std::string length = header_value(headers, "content-length");
    if (!length.empty()) {
        try { remaining = static_cast<size_t>(std::stoull(length)); }
        catch (...) { return false; }
        if (initial.size() > remaining) return false;
        remaining -= initial.size();
    }
    auto feed = [&](const std::string& bytes) {
        pending += bytes;
        if (pending.size() > 128 * 1024) return false;
        for (;;) {
            size_t lf = pending.find("\n\n");
            size_t crlf = pending.find("\r\n\r\n");
            size_t end = std::string::npos;
            size_t delimiter = 0;
            if (crlf != std::string::npos && (lf == std::string::npos || crlf <= lf)) { end = crlf + 4; delimiter = 4; }
            else if (lf != std::string::npos) { end = lf + 2; delimiter = 2; }
            if (end == std::string::npos) return true;
            std::string event = pending.substr(0, end);
            pending.erase(0, end);
            if (!send_chunk(client, restore ? restore(event) : event)) return false;
            (void)delimiter;
        }
    };
    if (!feed(initial)) return false;
    char buffer[8192];
    while (remaining > 0 || length.empty()) {
        size_t wanted = remaining ? std::min<size_t>(sizeof(buffer), remaining) : sizeof(buffer);
        int n = recv(upstream, buffer, static_cast<int>(wanted), 0);
        if (n <= 0) break;
        if (!feed(std::string(buffer, static_cast<size_t>(n)))) return false;
        if (remaining) remaining -= static_cast<size_t>(n);
    }
    if (!pending.empty() && !send_chunk(client, restore ? restore(pending) : pending)) return false;
    return send_all(client, "0\r\n\r\n");
}

void serve(Socket client, const Url& url, unsigned timeout_seconds, const ProszeProxyTransform& redact,
           const ProszeProxyTransform& restore)
{
    set_socket_timeout(client, timeout_seconds);
    std::string incoming;
    if (!receive_until(client, incoming, "\r\n\r\n", 64 * 1024)) { close_socket(client); return; }
    std::string request_line, body; size_t request_length = 0;
    std::vector<std::pair<std::string, std::string>> request_headers;
    if (!parse_request(incoming, request_line, request_headers, body, request_length) ||
        !receive_exact(client, body, request_length)) { close_socket(client); return; }
    std::istringstream request_stream(request_line);
    std::string method, target, version;
    request_stream >> method >> target >> version;
    if (target.empty() || target[0] != '/') target = "/";
    std::string redacted = redact ? redact(body) : body;
    Socket upstream = connect_upstream(url);
    if (upstream == invalid_socket) { close_socket(client); return; }
    set_socket_timeout(upstream, timeout_seconds);
    std::string path = url.prefix + target;
    if (path.empty() || path[0] != '/') path = "/" + path;
    std::ostringstream outbound;
    outbound << method << " " << path << " HTTP/1.1\r\nHost: " << url.host
             << "\r\nConnection: close\r\nAccept-Encoding: identity\r\n";
    for (const auto& header : request_headers) if (!hop_header(header.first))
        outbound << header.first << ": " << header.second << "\r\n";
    outbound << "Content-Length: " << redacted.size() << "\r\n\r\n" << redacted;
    if (!send_all(upstream, outbound.str())) { close_socket(upstream); close_socket(client); return; }

    std::string response;
    if (!receive_until(upstream, response, "\r\n\r\n", 64 * 1024)) { close_socket(upstream); close_socket(client); return; }
    size_t split = response.find("\r\n\r\n");
    std::istringstream response_stream(response.substr(0, split));
    std::string status_line, line;
    std::getline(response_stream, status_line);
    if (!status_line.empty() && status_line.back() == '\r') status_line.pop_back();
    std::vector<std::pair<std::string, std::string>> response_headers;
    while (std::getline(response_stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon != std::string::npos) response_headers.emplace_back(trim_copy(line.substr(0, colon)), trim_copy(line.substr(colon + 1)));
    }
    std::string encoding = lower_copy(header_value(response_headers, "content-encoding"));
    int status_code = 0;
    try { status_code = std::stoi(status_line.substr(status_line.find(' ') + 1)); } catch (...) { close_socket(upstream); close_socket(client); return; }
    bool no_body = method == "HEAD" || (status_code >= 100 && status_code < 200) ||
                   status_code == 204 || status_code == 304;
    std::string type = lower_copy(header_value(response_headers, "content-type"));
    if (!no_body && encoding.empty() && type.find("text/event-stream") != std::string::npos &&
        lower_copy(header_value(response_headers, "transfer-encoding")) != "chunked") {
        bool streamed = stream_sse(upstream, client, status_line, response_headers,
                                    response.substr(split + 4), restore);
        close_socket(upstream); close_socket(client); (void)streamed; return;
    }
    std::string data = no_body ? std::string() :
        read_response(upstream, response, response_headers, response.size() - split - 4);
    close_socket(upstream);
    if (!encoding.empty() && encoding != "identity") { close_socket(client); return; }
    if (type.find("json") != std::string::npos || type.find("text/") != std::string::npos) {
        data = type.find("json") != std::string::npos
            ? restore_json_strings(data, restore) : (restore ? restore(data) : data);
    }
    std::ostringstream result;
    result << status_line << "\r\n";
    for (const auto& header : response_headers)
        if (!hop_header(header.first) && lower_copy(header.first) != "content-encoding")
            result << header.first << ": " << header.second << "\r\n";
    result << "Content-Length: " << data.size() << "\r\nConnection: close\r\n\r\n" << data;
    send_all(client, result.str());
    close_socket(client);
}
} // namespace

int run_prosze_proxy(const ProszeProxyConfig& config,
                     ProszeProxyTransform redact, ProszeProxyTransform restore)
{
    if (config.listen_host != "127.0.0.1" && config.listen_host != "localhost") return 2;
    Url url;
    if (!parse_url(config.upstream, url)) return 2;
#ifdef _WIN32
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 1;
#endif
    Socket listener = static_cast<Socket>(socket(AF_INET, SOCK_STREAM, 0));
    if (listener == invalid_socket) { 
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(config.listen_port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 || listen(listener, 16) != 0) {
        close_socket(listener);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    for (;;) {
        Socket client = accept(listener, nullptr, nullptr);
        if (client == invalid_socket) break;
        std::thread([client, url, timeout_seconds = config.timeout_seconds, redact, restore]() mutable {
            serve(client, url, timeout_seconds, redact, restore);
        }).detach();
    }
    close_socket(listener);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
