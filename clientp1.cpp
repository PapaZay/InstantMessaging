#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <algorithm>
#include <signal.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Increased buffer size to handle larger responses
constexpr size_t MAXDATASIZE = 4096;
constexpr size_t MAX_INPUT_LENGTH = 1024;

// Global socket file descriptor for cleanup in signal handler
int global_sockfd = -1;
SSL* global_ssl = nullptr;
SSL_CTX* global_ctx = nullptr;

void cleanup() {
    if (global_ssl) {
        SSL_shutdown(global_ssl);
        SSL_free(global_ssl);
    }
    if (global_ctx) {
        SSL_CTX_free(global_ctx);
    }
    if (global_sockfd != -1) {
        close(global_sockfd);
    }
}


void signal_handler(int signum) {
    cleanup();
    exit(signum);
}

void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Enhanced send function with error handling and partial send handling
bool sendAll(SSL* ssl, const std::string& data) {
    size_t total_sent = 0;
    size_t len = data.length();
    
    while (total_sent < len) {
        int sent = SSL_write(ssl, data.c_str() + total_sent, len - total_sent);
        if (sent <= 0) {
            int err = SSL_get_error(ssl, sent);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                continue;
            }
            ERR_print_errors_fp(stderr);
            return false;
        }
        total_sent += sent;
    }
    return true;
}

// Enhanced receive function
ssize_t recvAll(SSL* ssl, char* buf, size_t maxlen) {
    size_t total_received = 0;
    int n;
    
    while (total_received < maxlen - 1) {
        n = SSL_read(ssl, buf + total_received, maxlen - total_received - 1);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            if (err == SSL_ERROR_ZERO_RETURN) {
                break; // Connection closed
            }
            ERR_print_errors_fp(stderr);
            return -1;
        }
        total_received += n;
        
        // Check if we've received a complete message
        if (buf[total_received - 1] == '\n') break;
    }
    
    buf[total_received] = '\0';
    return total_received;
}

// Initialize SSL context
SSL_CTX* initialize_ssl_context() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_print_errors_fp(stderr); 
    
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    // Set TLS 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    return ctx;
}


class ClientState {
public:
    bool heloSent = false;
    bool searchMode = false;
    bool manageMode = false;
    bool recommendMode = false;
    
    void resetModes() {
        searchMode = false;
        manageMode = false;
        recommendMode = false;
    }

    
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "usage: client client.conf\n";
        return 1;
    }

    // Set up signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize SSL
    SSL_CTX* ctx = initialize_ssl_context();
    if (!ctx) {
        std::cerr << "Failed to initialize SSL context\n";
        return 1;
    }
    global_ctx = ctx;

    // Read configuration from file
    std::string serverIP, serverPort;
    std::ifstream configFile(argv[1]);
    if (!configFile.is_open()) {
        std::cerr << "Error opening config file: " << argv[1] << std::endl;
        cleanup();
        return 1;
    }

    std::string line;
    while (std::getline(configFile, line)) {
        if (line.find("SERVER_IP=") == 0) {
            serverIP = line.substr(10);
        } else if (line.find("SERVER_PORT=") == 0) {
            serverPort = line.substr(12);
        }
    }
    configFile.close();

    if (serverIP.empty() || serverPort.empty()) {
        std::cerr << "Invalid config file format.\n";
        cleanup();
        return 1;
    }

    // Set up connection
    addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rv = getaddrinfo(serverIP.c_str(), serverPort.c_str(), &hints, &servinfo);
    if (rv != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        cleanup();
        return 1;
    }

    int sockfd;
    for (p = servinfo; p != nullptr; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("client: socket");
            continue;
        }

        // Set socket timeout
        struct timeval tv;
        tv.tv_sec = 30;  // 30 second timeout
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("client: connect");
            close(sockfd);
            continue;
        }
        break;
    }

    if (p == nullptr) {
        std::cerr << "client: failed to connect\n";
        freeaddrinfo(servinfo);
        cleanup();
        return 2;
    }

    global_sockfd = sockfd;  // Store for signal handler

    char s[INET6_ADDRSTRLEN];
    inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), s, sizeof s);
    std::cout << "client: connecting to " << s << std::endl;

    freeaddrinfo(servinfo);

    // Initialize SSL connection
    SSL* ssl = SSL_new(ctx);
    std::cout << "SSL structure created" << std::endl;

    if (!ssl) {
        std::cerr << "Failed to create SSL structure\n";
        cleanup();
        return 1;
    }
    global_ssl = ssl;

    SSL_set_fd(ssl, sockfd);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        cleanup();
        return 1;
    }

    std::cout << "SSL connection established using " << SSL_get_cipher(ssl) << std::endl;
    std::cout << "Server certificate:" << std::endl;
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        char* line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        std::cout << "Subject: " << line << std::endl;
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        std::cout << "Issuer: " << line << std::endl;
        free(line);
        X509_free(cert);
    } else {
        std::cout << "No certificate provided by server" << std::endl;
    }

    char buf[MAXDATASIZE];
    std::string userInput;
    ClientState state;
    const std::string hostname = "client_hostname";

    std::cout << "\nWelcome to the Library Management System\n";
    std::cout << "Please start with the HELO command\n";

    while (true) {
        std::cout << "> ";
        std::getline(std::cin, userInput);

        // Handle EOF (Ctrl+D)
        if (std::cin.eof()) {
            std::cout << "\nReceived EOF, exiting...\n";
            break;
        }

        // Input validation
        if (userInput.empty()) {
            std::cout << "Empty input, please try again\n";
            continue;
        }
        if (userInput.length() > MAX_INPUT_LENGTH) {
            std::cout << "Input too long (max " << MAX_INPUT_LENGTH << " characters)\n";
            continue;
        }

        // Command processing
        std::string command = userInput;
        std::transform(command.begin(), command.end(), command.begin(), ::toupper);

        if (command == "BYE") {
            if (!sendAll(ssl, command)) break;
            if (recvAll(ssl, buf, MAXDATASIZE) <= 0) break;
            std::cout << buf;
            break;
        }

        if (!state.heloSent) {
            if (command == "HELO") {
                std::string fullCommand = "HELO " + hostname + "\n";
                if (!sendAll(ssl, fullCommand)) break;
                if (recvAll(ssl, buf, MAXDATASIZE) <= 0) break;
                std::cout << buf;
                state.heloSent = true;
                continue;
            } else {
                std::cout << "Please run 'HELO' command first.\n";
                continue;
            }
        }

        // Mode handling
        if (command == "SEARCH") {
            state.resetModes();
            state.searchMode = true;
        } else if (command == "MANAGE") {
            state.resetModes();
            state.manageMode = true;
        } else if (command == "RECOMMEND") {
            state.resetModes();
            state.recommendMode = true;
        }

        // Send command to server using SSL
        if (!sendAll(ssl, userInput)) break;
        ssize_t numbytes = recvAll(ssl, buf, MAXDATASIZE);
        if (numbytes <= 0) break;

        std::cout << buf;

        // Mode-specific help
        if ((state.searchMode && command != "SEARCH" && command != "HELP" && 
             command.find("FIND ") != 0 && command.find("DETAILS ") != 0)) {
            std::cout << "Search mode commands:\n"
                     << "FIND <term> - Search for books\n"
                     << "DETAILS \"<title>\" - Get book details\n";
        } else if ((state.manageMode && command != "MANAGE" && command != "HELP" &&
                   command.find("CHECKOUT ") != 0 && command.find("RETURN ") != 0 && 
                   command != "LIST")) {
            std::cout << "Management mode commands:\n"
                     << "CHECKOUT \"<title>\" - Check out a book\n"
                     << "RETURN \"<title>\" - Return a book\n"
                     << "LIST - List available books\n";
        } else if ((state.recommendMode && command != "RECOMMEND" && command != "HELP" &&
                   command.find("GET ") != 0 && command.find("RATE ") != 0)) {
            std::cout << "Recommendation mode commands:\n"
                     << "GET <genre> - Get recommendations\n"
                     << "RATE \"<title>\" <1-5> - Rate a book\n";
        }
    }

    cleanup();
    return 0;
}