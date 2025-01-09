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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sstream>
#include <iomanip>

constexpr size_t MAXDATASIZE = 4096;
#define PSK "F24447TG"

void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


std::string toLowerCase(const std::string& str) {
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);
    return lowerStr;
}

std::string encryptDecrypt(const std::string& input, bool encrypt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    
    
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
                   (unsigned char*)PSK, strlen(PSK),
                   1, key, iv);
    
    if (encrypt) {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    } else {
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    }
    
    std::vector<unsigned char> out(input.size() + EVP_MAX_BLOCK_LENGTH);
    int outlen1, outlen2;
    
    if (encrypt) {
        EVP_EncryptUpdate(ctx, out.data(), &outlen1,
                         (unsigned char*)input.c_str(), input.size());
        EVP_EncryptFinal_ex(ctx, out.data() + outlen1, &outlen2);
    } else {
        EVP_DecryptUpdate(ctx, out.data(), &outlen1,
                         (unsigned char*)input.c_str(), input.size());
        EVP_DecryptFinal_ex(ctx, out.data() + outlen1, &outlen2);
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    return std::string((char*)out.data(), outlen1 + outlen2);
}

SSL_CTX* create_ssl_context() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

   
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    
    return ctx;
}

bool isStrongPassword(const std::string& password) {
    //  5 characters
    if (password.length() != 5) {
        return false;
    }
    
    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;
    const std::string specialChars = "!@#$%^&*";
    
    for (char c : password) {
        if (std::isupper(c)) hasUpper = true;
        else if (std::islower(c)) hasLower = true;
        else if (std::isdigit(c)) hasDigit = true;
        else if (specialChars.find(c) != std::string::npos) hasSpecial = true;
    }
    
    
    int typesCount = hasUpper + hasLower + hasDigit + hasSpecial;
    if (typesCount < 3) {
        return false;
    }
    
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "usage: client client.conf\n";
        return 1;
    }

    
    std::string serverIP, serverPort;
    std::ifstream configFile(argv[1]);
    if (!configFile.is_open()) {
        std::cerr << "Error opening config file: " << argv[1] << std::endl;
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
        return 1;
    }

    
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    SSL_CTX* ssl_ctx = create_ssl_context();

    addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rv = getaddrinfo(serverIP.c_str(), serverPort.c_str(), &hints, &servinfo);
    if (rv != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return 1;
    }

    int sockfd;
    for (p = servinfo; p != nullptr; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("client: connect");
            close(sockfd);
            continue;
        }

        break;
    }

    if (p == nullptr) {
        std::cerr << "client: failed to connect\n";
        return 2;
    }

    char s[INET6_ADDRSTRLEN];
    inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), s, sizeof s);
    std::cout << "client: connecting to " << s << std::endl;

    freeaddrinfo(servinfo);

    SSL* ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        std::cerr << "Error creating SSL structure" << std::endl;
        close(sockfd);
        return 1;
    }

    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        std::cerr << "Error during SSL handshake" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        return 1;
    }

    char buf[MAXDATASIZE];
    std::string userInput;
    bool authenticated = false;
    bool SearchMode = false;
    bool manageMode = false;
    bool recommendMode = false;

    std::cout << "Enter username: ";
    std::string username;
    std::getline(std::cin, username);
    
    std::string userCommand = "USER " + username;
    if (SSL_write(ssl, userCommand.c_str(), userCommand.length()) <= 0) {
        std::cerr << "Error sending username" << std::endl;
        SSL_free(ssl);
        close(sockfd);
        return 1;
    }

    int numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
    if (numbytes <= 0) {
        std::cerr << "Error receiving server response" << std::endl;
        SSL_free(ssl);
        close(sockfd);
        return 1;
    }
    buf[numbytes] = '\0';
    std::cout << "Server: " << buf << std::endl;

    if (std::string(buf).find("230") == 0) {
        std::string response(buf);
        size_t start = response.find("password: ") + 10;
        std::string encryptedPassword = response.substr(start);
        
        try {
            std::string password = encryptDecrypt(encryptedPassword, false);
            std::cout << "Your generated password is: " << password << std::endl;
            std::cout << "Please reconnect and login with these credentials." << std::endl;
            SSL_free(ssl);
            close(sockfd);
            return 0;
        } catch (const std::exception& e) {
            std::cerr << "Error decrypting password" << std::endl;
            SSL_free(ssl);
            close(sockfd);
            return 1;
        }
    }

    std::cout << "Enter password: ";
    std::string password;
    std::getline(std::cin, password);

    if (!isStrongPassword(password)) {
        std::cout << "Password must be 5 characters and contain at least 3 of the following:\n"
                  << "- Uppercase letters\n"
                  << "- Lowercase letters\n"
                  << "- Numbers\n"
                  << "- Special characters (!@#$%^&*)\n";
        SSL_free(ssl);
        close(sockfd);
        return 1;
    }

    std::string encryptedPassword;
    try {
        encryptedPassword = encryptDecrypt(password, true);
    } catch (const std::exception& e) {
        std::cerr << "Error encrypting password" << std::endl;
        SSL_free(ssl);
        close(sockfd);
        return 1;
    }

    std::string passCommand = "PASS " + encryptedPassword;
    if (SSL_write(ssl, passCommand.c_str(), passCommand.length()) <= 0) {
        std::cerr << "Error sending password" << std::endl;
        SSL_free(ssl);
        close(sockfd);
        return 1;
    }

    numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
    if (numbytes <= 0) {
        std::cerr << "Error receiving server response" << std::endl;
        SSL_free(ssl);
        close(sockfd);
        return 1;
    }
    buf[numbytes] = '\0';
    std::cout << "Server: " << buf << std::endl;

    if (std::string(buf).find("230") == 0) {
        authenticated = true;
    } else {
        std::cout << "Authentication failed. Please try again." << std::endl;
        SSL_free(ssl);
        close(sockfd);
        return 1;
    }

    while (authenticated) {
        std::cout << "> ";
        std::getline(std::cin, userInput);
        std::string command = userInput;

        if (command == "BYE") {
            if (SSL_write(ssl, userInput.c_str(), userInput.length()) <= 0) {
                std::cerr << "Error sending command" << std::endl;
                break;
            }

            numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
            if (numbytes <= 0) {
                std::cerr << "Error receiving response" << std::endl;
                break;
            }

            buf[numbytes] = '\0';
            std::cout << "Server: " << buf << std::endl;
            break;
        }

        if (command == "HELP") {
            if (SSL_write(ssl, userInput.c_str(), userInput.length()) <= 0) {
                std::cerr << "Error sending command" << std::endl;
                break;
            }

            numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
            if (numbytes <= 0) {
                std::cerr << "Error receiving response" << std::endl;
                break;
            }

            buf[numbytes] = '\0';
            std::cout << "Server: " << buf << std::endl;
            continue;
        }

        if (command == "SEARCH") {
            if (SSL_write(ssl, userInput.c_str(), userInput.length()) <= 0) {
                std::cerr << "Error sending command" << std::endl;
                break;
            }

            numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
            if (numbytes <= 0) {
                std::cerr << "Error receiving response" << std::endl;
                break;
            }

            buf[numbytes] = '\0';
            std::cout << "Server: " << buf << std::endl;
            SearchMode = true;
            manageMode = false;
            recommendMode = false;
            continue;
        }

        if (SearchMode && (command.find("FIND ") == 0 || command.find("DETAILS ") == 0)) {
            if (SSL_write(ssl, userInput.c_str(), userInput.length()) <= 0) {
                std::cerr << "Error sending command" << std::endl;
                break;
            }

            numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
            if (numbytes <= 0) {
                std::cerr << "Error receiving response" << std::endl;
                break;
            }

            buf[numbytes] = '\0';
            std::cout << "Server: " << buf << std::endl;
            continue;
        }

        if (command == "MANAGE") {
            if (SSL_write(ssl, userInput.c_str(), userInput.length()) <= 0) {
                std::cerr << "Error sending command" << std::endl;
                break;
            }

            numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
            if (numbytes <= 0) {
                std::cerr << "Error receiving response" << std::endl;
                break;
            }

            buf[numbytes] = '\0';
            std::cout << "Server: " << buf << std::endl;
            manageMode = true;
            SearchMode = false;
            recommendMode = false;
            continue;
        }

        if (manageMode && (command.find("CHECKOUT ") == 0 || command.find("RETURN ") == 0 || command == "LIST")) {
            if (SSL_write(ssl, userInput.c_str(), userInput.length()) <= 0) {
                std::cerr << "Error sending command" << std::endl;
                break;
            }

            numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
            if (numbytes <= 0) {
                std::cerr << "Error receiving response" << std::endl;
                break;
            }

            buf[numbytes] = '\0';
            std::cout << "Server: " << buf << std::endl;
            continue;
        }

        if (command == "RECOMMEND") {
            if (SSL_write(ssl, userInput.c_str(), userInput.length()) <= 0) {
                std::cerr << "Error sending command" << std::endl;
                break;
            }

            numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
            if (numbytes <= 0) {
                std::cerr << "Error receiving response" << std::endl;
                break;
            }

            buf[numbytes] = '\0';
            std::cout << "Server: " << buf << std::endl;
            recommendMode = true;
            SearchMode = false;
            manageMode = false;
            continue;
        }

        if (recommendMode && (command.find("GET ") == 0 || command.find("RATE ") == 0)) {
            if (SSL_write(ssl, userInput.c_str(), userInput.length()) <= 0) {
                std::cerr << "Error sending command" << std::endl;
                break;
            }

            numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
            if (numbytes <= 0) {
                std::cerr << "Error receiving response" << std::endl;
                break;
            }

            buf[numbytes] = '\0';
            std::cout << "Server: " << buf << std::endl;
            continue;
        }

        std::cout << "Invalid command. Type HELP for available commands.\n";
    }

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();
    close(sockfd);
    return 0;
}
