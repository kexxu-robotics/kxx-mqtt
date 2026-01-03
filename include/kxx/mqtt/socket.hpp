#pragma once

// Linux/Unix only
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <poll.h>

typedef int socket_t;
#define INVALID_SOCKET_VALUE -1
#define SOCKET_ERROR_VALUE -1
#define CLOSE_SOCKET close
#define LAST_ERROR errno

#include <cstring>
#include <string>
#include <stdexcept>
#include <memory>
#include <vector>
#include <chrono>
#include <mutex>
#include <atomic>
#include <expected>

namespace kxx::mqtt {

    // Forward declarations
    class TLSSocket;
    struct TLSConfig;

    // Main Socket class
    class Socket {
    protected:
        socket_t fd_;
        std::atomic<bool> is_connected_;
        mutable std::mutex socket_mutex_;

        // Internal close without lock
        void close_internal() {
            if (fd_ != INVALID_SOCKET_VALUE) {
                ::shutdown(fd_, SHUT_RDWR);
                ::close(fd_);
                fd_ = INVALID_SOCKET_VALUE;
                is_connected_ = false;
            }
        }

    public:

        static int get_last_error() {
            return errno;
        }

        Socket() : fd_(INVALID_SOCKET_VALUE), is_connected_(false) {
        }

        explicit Socket(socket_t fd) : fd_(fd), is_connected_(true) {
        }

        virtual ~Socket() {
            close();
        }

        // Move constructor
        Socket(Socket&& other) noexcept
            : fd_(INVALID_SOCKET_VALUE), is_connected_(false) {
            std::lock_guard<std::mutex> lock(other.socket_mutex_);
            fd_ = other.fd_;
            is_connected_ = other.is_connected_.load();
            other.fd_ = INVALID_SOCKET_VALUE;
            other.is_connected_ = false;
        }

        // Move assignment - CORRECTED to avoid deadlock
        Socket& operator=(Socket&& other) noexcept {
            if (this != &other) {
                // Use std::lock to avoid deadlock
                std::unique_lock<std::mutex> lock1(socket_mutex_, std::defer_lock);
                std::unique_lock<std::mutex> lock2(other.socket_mutex_, std::defer_lock);
                std::lock(lock1, lock2);

                close_internal();
                fd_ = other.fd_;
                is_connected_ = other.is_connected_.load();
                other.fd_ = INVALID_SOCKET_VALUE;
                other.is_connected_ = false;
            }
            return *this;
        }

        // Delete copy operations
        Socket(const Socket&) = delete;
        Socket& operator=(const Socket&) = delete;

        // Factory method
        static std::unique_ptr<Socket> create(bool use_tls, const TLSConfig* config = nullptr);

        // Socket creation
        bool create() {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ != INVALID_SOCKET_VALUE) {
                return false;
            }

            fd_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (fd_ == INVALID_SOCKET_VALUE) {
                return false;
            }

            return true;
        }

        // Set non-blocking mode
        bool set_non_blocking(bool enable) {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE) return false;

            int flags = fcntl(fd_, F_GETFL, 0);
            if (flags == -1) return false;

            if (enable) {
                flags |= O_NONBLOCK;
            }
            else {
                flags &= ~O_NONBLOCK;
            }

            return fcntl(fd_, F_SETFL, flags) != -1;
        }

        // Set reuse address
        bool set_reuse_address(bool enable) {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE) return false;

            int flag = enable ? 1 : 0;
            return setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR,
                &flag, sizeof(flag)) == 0;
        }

        // Set TCP nodelay
        bool set_tcp_nodelay(bool enable) {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE) return false;

            int flag = enable ? 1 : 0;
            return setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY,
                &flag, sizeof(flag)) == 0;
        }

        bool set_nodelay(bool enable) {
            return set_tcp_nodelay(enable);
        }

        // Set buffer sizes
        bool set_send_buffer_size(int size) {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE) return false;

            return setsockopt(fd_, SOL_SOCKET, SO_SNDBUF,
                &size, sizeof(size)) == 0;
        }

        bool set_receive_buffer_size(int size) {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE) return false;

            return setsockopt(fd_, SOL_SOCKET, SO_RCVBUF,
                &size, sizeof(size)) == 0;
        }

        // Set timeouts
        bool set_receive_timeout(int timeout_ms) {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE) return false;

            struct timeval tv;
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            return setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO,
                &tv, sizeof(tv)) == 0;
        }

        bool set_send_timeout(int timeout_ms) {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE) return false;

            struct timeval tv;
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            return setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO,
                &tv, sizeof(tv)) == 0;
        }

        // Server operations
        bool bind(uint16_t port, const std::string& address = "") {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE) return false;

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);

            if (address.empty()) {
                addr.sin_addr.s_addr = INADDR_ANY;
            }
            else {
                if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) <= 0) {
                    return false;
                }
            }

            return ::bind(fd_, (sockaddr*)&addr, sizeof(addr)) == 0;
        }

        bool listen(int backlog = 128) {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE) return false;
            return ::listen(fd_, backlog) == 0;
        }

        Socket accept() {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE) {
                return Socket();
            }

            sockaddr_in client_addr{};
            socklen_t len = sizeof(client_addr);

            socket_t client_fd = ::accept(fd_, (sockaddr*)&client_addr, &len);
            if (client_fd != INVALID_SOCKET_VALUE) {
                return Socket(client_fd);
            }

            return Socket();
        }

        std::expected<void, std::string> connect(const std::string& host, uint16_t port) {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            const std::string service = std::to_string(port);

            addrinfo hints{};
            hints.ai_family   = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            addrinfo* res = nullptr;
            const int gai_rc = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &res);
            if (gai_rc != 0){
              std::string msg = ::gai_strerror(gai_rc);
              return std::unexpected(msg);
            }

            struct ResGuard { addrinfo* p{}; ~ResGuard(){ if(p) ::freeaddrinfo(p);} } guard{res};

            // Close any existing socket first (optional; depends on your semantics)
            close_internal();

            for (addrinfo* ai = res; ai; ai = ai->ai_next) {
                socket_t s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
                if (s == INVALID_SOCKET_VALUE) continue;

                // If your class supports non-blocking by option, apply it here.
                // Example:
                // int flags = fcntl(s, F_GETFL, 0);
                // fcntl(s, F_SETFL, flags | O_NONBLOCK);

                const int rc = ::connect(s, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen));
                if (rc == 0) {
                    fd_ = s;
                    is_connected_ = true;
                    return {};
                }

                const int e = errno;
                if (e == EINPROGRESS || e == EWOULDBLOCK || e == EAGAIN) {
                    fd_ = s;
                    is_connected_ = false; // connecting
                    return std::unexpected("Connecting in progress");
                }

                ::close(s);
            }

            return std::unexpected("Could not connect");;
        }


        bool wait_for_connect(int timeout_ms) {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE) return false;
            struct pollfd pfd;
            pfd.fd = fd_;
            pfd.events = POLLOUT;

            int result = poll(&pfd, 1, timeout_ms);

            if (result > 0) {
                int error = 0;
                socklen_t len = sizeof(error);
                if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
                    if (error == 0) {
                        is_connected_ = true;
                        return true;
                    }
                }
            }
            return false;
        }

        // Data transfer
        virtual int send(const void* data, size_t len) {
            return send(static_cast<const uint8_t*>(data), len);
        }

        virtual int send(const uint8_t* data, size_t len) {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE || !data || len == 0) return -1;

            return ::send(fd_, data, len, MSG_NOSIGNAL);
        }

        int send(const std::string& data) {
            return send(data.c_str(), data.length());
        }

        int send(const char* data, size_t len) {
            return send(static_cast<const void*>(data), len);
        }

        virtual int receive(void* buffer, size_t max_len) {
            return receive(static_cast<uint8_t*>(buffer), max_len);
        }

        virtual int receive(uint8_t* buffer, size_t max_len) {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE || !buffer || max_len == 0) return -1;

            return ::recv(fd_, buffer, max_len, 0);
        }

        int receive(char* buffer, size_t max_len) {
            return receive(static_cast<void*>(buffer), max_len);
        }

        // Socket state
        void close() {
            std::lock_guard<std::mutex> lock(socket_mutex_);
            close_internal();
        }

        bool is_valid() const {
            std::lock_guard<std::mutex> lock(socket_mutex_);
            return fd_ != INVALID_SOCKET_VALUE;
        }

        bool is_connected() const {
            return is_connected_.load() && is_valid();
        }

        socket_t get_handle() const {
            std::lock_guard<std::mutex> lock(socket_mutex_);
            return fd_;
        }

        virtual bool is_tls() const {
            return false;
        }

        bool would_block() const {
            return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS);
        }

        // Get peer address
        std::string get_peer_address() const {
            std::lock_guard<std::mutex> lock(socket_mutex_);

            if (fd_ == INVALID_SOCKET_VALUE) return "";

            sockaddr_in addr{};
            socklen_t len = sizeof(addr);

            if (getpeername(fd_, (sockaddr*)&addr, &len) == 0) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr.sin_addr, ip_str, INET_ADDRSTRLEN);
                return std::string(ip_str) + ":" + std::to_string(ntohs(addr.sin_port));
            }

            return "";
        }

        // Error handling

        bool set_reuse_port(bool enable) {
           int opt = enable ? 1 : 0;
           return setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT,
               reinterpret_cast<const char*>(&opt), sizeof(opt)) == 0;
        }

        static std::string get_last_error_string() {
            return std::string(strerror(errno));
        }

        static int get_last_error_code() {
            return errno;
        }
    };

} // namespace kxx::mqtt

