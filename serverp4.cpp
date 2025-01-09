#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <cerrno>
#include <system_error>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <random>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

#define BACKLOG 10
#define MAXDATASIZE 4096
#define PSK "F24447TG"  
#define SALT_LENGTH 6
#define PASSWORD_LENGTH 5
#define SHADOW_FILE ".book_shadow"

struct User {
    std::string username;
    std::string salt;
    std::string passwordHash;
};

struct Book {
    int id;
    std::string title;
    std::string author;
    std::string genre;
    bool available; // true if available for checkout, false otherwise
    int rating; // 1-5 stars, 0 if not yet rated
};

std::vector<Book> loadBooksFromFile(const std::string& filename) {
    std::vector<Book> books;
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open books database file");
    }

    std::string line;
    std::getline(file, line); 

    while (std::getline(file, line)) {
        try {
            std::stringstream ss(line);
            std::string id_str, title, author, genre, available_str, rating_str;

            std::getline(ss, id_str, ';');
            std::getline(ss, title, ';');
            std::getline(ss, author, ';');
            std::getline(ss, genre, ';');
            std::getline(ss, available_str, ';');
            std::getline(ss, rating_str, ';');

            int id = std::stoi(id_str);
            Book book;
            book.id = id;
            book.title = title;
            book.author = author;
            book.genre = genre;
            book.available = (available_str == "true");
            book.rating = std::stoi(rating_str);

            books.push_back(book);
        } catch (const std::exception& e) {
            throw std::runtime_error("Error parsing line: " + line + "\nError: " + e.what());
        }
    }

    if (books.empty()) {
        throw std::runtime_error("No books found in database");
    }

    return books;
}

void sigchld_handler(int s)
{
    (void)s;

    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

void* get_in_addr(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

std::string toCamelCase(const std::string& input)
{
    std::string output;
    bool capitalize = true;

    for (char c : input) {
        if (std::isalpha(c)) {
            if (capitalize) {
                output += std::toupper(c);
            } else {
                output += std::tolower(c);
            }
            capitalize = !capitalize;
        } else {
            output += c;
        }
    }
    return output;
}

void logConnection(const std::string& clientIP)
{
    time_t now = time(nullptr); 
    tm* localTime = localtime(&now); 
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localTime);
    std::cout << "[" << timestamp << "] Connection from: " << clientIP << std::endl;
}

void logDisconnection(const std::string& clientIP)
{
    time_t now = time(nullptr);  
    tm* localTime = localtime(&now); 
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localTime);
    std::cout << "[" << timestamp << "] Client disconnected: " << clientIP << std::endl;
}

std::string generateRandomString(int length, bool isPassword = false) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const char symbols[] = "!@#$%&*";
    std::string result;
    
    unsigned char rand_bytes[32];
    if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    
    std::mt19937 gen(std::random_device{}());
    
    if (isPassword) {
        result += charset[26 + (rand_bytes[0] % 26)]; // uppercase
        result += charset[52 + (rand_bytes[1] % 10)]; // number
        result += symbols[rand_bytes[2] % (sizeof(symbols) - 1)]; // symbol
        
        for (int i = 3; i < length; i++) {
            result += charset[rand_bytes[i] % (sizeof(charset) - 1)];
        }
        
        std::shuffle(result.begin(), result.end(), gen);
        
        if (!std::isalnum(result[0])) {
            for (size_t i = 1; i < result.length(); i++) {
                if (std::isalnum(result[i])) {
                    std::swap(result[0], result[i]);
                    break;
                }
            }
        }
    } else {
        // generate salt
        for (int i = 0; i < length; i++) {
            result += charset[rand_bytes[i] % (sizeof(charset) - 1)];
        }
    }
    
    return result;
}


std::string saltPassword(const std::string& password, const std::string& salt) {
    std::string salted;
    size_t maxLength = std::max(password.length(), salt.length());
    
    for (size_t i = 0; i < maxLength; i++) {
        if (i < salt.length()) salted += salt[i];
        if (i < password.length()) salted += password[i];
    }
    
    return salted;
}

bool isPasswordEncrypted(const std::string& password) {
    bool hasNonPrintable = false;
    bool hasReasonableLength = password.length() > 5;  // encrypted version will be longer than plain 5 chars
    
    for (char c : password) {
        if (!std::isprint(c)) {
            hasNonPrintable = true;
            break;
        }
    }
    
    return hasNonPrintable && hasReasonableLength;
}


std::string generateHash(const std::string& input) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, input.c_str(), input.length());
    SHA512_Final(hash, &sha512);
    
    std::stringstream ss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
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

bool isStrongPassword(const std::string& password) {
    // 5 characters
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
    
    for (size_t i = 0; i < password.length() - 1; i++) {
        if (std::isalnum(password[i]) && std::isalnum(password[i+1])) {
            if (std::tolower(password[i+1]) == std::tolower(password[i]) + 1) {
                return false;
            }
        }
    }
    
    for (size_t i = 0; i < password.length() - 1; i++) {
        if (password[i] == password[i + 1]) {
            return false;
        }
    }
    
    return true;
}

void saveUser(const User& user) {
    std::ofstream shadowFile(SHADOW_FILE, std::ios::app);
    if (!shadowFile) {
        throw std::runtime_error("Failed to open shadow file");
    }
    shadowFile << user.username << ":" << user.salt << ":" << user.passwordHash << "\n";
}

std::vector<User> loadUsers() {
    std::vector<User> users;
    std::ifstream shadowFile(SHADOW_FILE);
    if (!shadowFile) {
        return users;
    }
    
    std::string line;
    while (std::getline(shadowFile, line)) {
        std::stringstream ss(line);
        std::string username, salt, hash;
        std::getline(ss, username, ':');
        std::getline(ss, salt, ':');
        std::getline(ss, hash);
        users.push_back({username, salt, hash});
    }
    
    return users;
}

std::string formatResponse(const std::string& code, const std::string& message) {
    std::string fullResponse = code + " " + message;
    
    if (fullResponse.length() >= MAXDATASIZE) {
        size_t maxLength = MAXDATASIZE - code.length() - 10;  
        return code + " " + message.substr(0, maxLength) + "...\n";
    }
    return fullResponse;
}


std::string findBooksByTerm(const std::vector<Book>& books, const std::string& searchTerm) {
    std::string results;
    int count = 0;
    for (size_t i = 0; i < books.size(); i++) {
        const auto& book = books[i];
        if (book.title.find(searchTerm) != std::string::npos || 
            book.author.find(searchTerm) != std::string::npos) {
            results += book.title + " by " + book.author + "\n";
            count++;
        }
    }
    return formatResponse(count > 0 ? "250" : "304", 
                        count > 0 ? "Books found:\n" + results : "No books found.");
}

int findBookByTitle(const std::vector<Book>& books, const std::string& title) {
    std::string searchTitle = title;
    std::transform(searchTitle.begin(), searchTitle.end(), searchTitle.begin(), ::tolower);
    
    for (const auto& book : books) {
        std::string bookTitle = book.title;
        std::transform(bookTitle.begin(), bookTitle.end(), bookTitle.begin(), ::tolower);
        if (bookTitle == searchTitle) {
            return book.id;  
        }
    }
    return -1;
}

std::string getBookDetailsById(const std::vector<Book>& books, const std::string& title) {
    int id = findBookByTitle(books, title);
    if (id == -1) {
        return formatResponse("404", "Book not found.");
    }

    const Book& book = books[id];
    std::stringstream ss;
    ss << "Title: " << book.title << "\n"
       << "Author: " << book.author << "\n"
       << "Genre: " << book.genre << "\n"
       << "Status: " << (book.available ? "Available" : "Checked Out") << "\n"
       << "Rating: " << book.rating << "/5";
    return formatResponse("250", ss.str());
}

std::string checkoutBook(const std::string& title, std::vector<Book>& books) {
    int id = findBookByTitle(books, title);
    if (id == -1) {
        return formatResponse("404", "Book not found.");
    }
    
    if (!books[id].available) {
        return formatResponse("403", "Book is already checked out.");
    }

    books[id].available = false;

    std::ofstream outFile("books.db");
    outFile << "ID;Title;Author;Genre;Available;Rating\n";
    for (const auto& book : books) {
        outFile << book.id << ";"
                << book.title << ";"
                << book.author << ";"
                << book.genre << ";"
                << (book.available ? "true" : "false") << ";"
                << book.rating << "\n";
    }
    outFile.close();

    return formatResponse("250", "Successfully checked out: " + books[id].title);
}

std::string returnBook(const std::string& title, std::vector<Book>& books) {
    int id = findBookByTitle(books, title);
    if (id == -1) {
        return formatResponse("404", "Book not found.");
    }
    
    if (books[id].available) {
        return formatResponse("403", "Book was not checked out.");
    }

    books[id].available = true;
    std::ofstream outFile("books.db");
    outFile << "ID;Title;Author;Genre;Available;Rating\n";
    for (const auto& book : books) {
        outFile << book.id << ";"
                << book.title << ";"
                << book.author << ";"
                << book.genre << ";"
                << (book.available ? "true" : "false") << ";"
                << book.rating << "\n";
    }
    outFile.close();

    return formatResponse("250", "Successfully returned: " + books[id].title);
}

std::string rateBook(const std::string& title, int rating, std::vector<Book>& books) {
    int id = findBookByTitle(books, title);
    if (id == -1) {
        return formatResponse("404", "Book not found.");
    }

    if (rating < 1 || rating > 5) {
        return formatResponse("400", "Rating must be between 1 and 5.");
    }

    books[id].rating = rating;

    std::ofstream outFile("books.db");
    outFile << "ID;Title;Author;Genre;Available;Rating\n";
    for (const auto& book : books) {
        outFile << book.id << ";"
                << book.title << ";"
                << book.author << ";"
                << book.genre << ";"
                << (book.available ? "true" : "false") << ";"
                << book.rating << "\n";
    }
    outFile.close();

    return formatResponse("250", "Rating updated successfully for: " + books[id].title);
}

std::string listAvailableBooks(const std::vector<Book>& books) {
    std::stringstream ss;
    int count = 0;

    for (const auto& book : books) {
        if (book.available) {
            count++;
        }
    }
    
    if (count == 0) {
        return formatResponse("304", "No books available.");
    }
    
    ss << "Available books:\n";
    
    for (const auto& book : books) {
        if (book.available) {
            ss << book.title << " by " << book.author << "\n";
        }
    }
    
    std::string response = formatResponse("250", ss.str());
    if (response.length() >= MAXDATASIZE) {
        ss.str("");
        ss.clear();
        ss << "Available books (showing first " << MAXDATASIZE/100 << " results):\n";
        int shown = 0;
        
        for (const auto& book : books) {
            if (book.available) {
                std::string entry = book.title + " by " + book.author + "\n";
                if (ss.str().length() + entry.length() + 50 < MAXDATASIZE) {  
                    ss << entry;
                    shown++;
                } else {
                    break;
                }
            }
        }
        
        if (shown < count) {
            ss << "... and " << (count - shown) << " more books\n";
        }
        
        response = formatResponse("250", ss.str());
    }
    
    return response;
}

std::string recommendBooksByGenre(const std::string& genre, const std::vector<Book>& books) {
    std::stringstream ss;
    int count = 0;
    for (const auto& book : books) {
        if (book.genre == genre && book.available) {
            ss << book.id << ". " << book.title << " by " << book.author 
               << " (Rating: " << book.rating << "/5)\n";
            count++;
        }
    }
    return formatResponse(count > 0 ? "250" : "304",
                        count > 0 ? "Recommended books:\n" + ss.str() : "No recommendations found.");
}

SSL_CTX* create_ssl_context() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256") <= 0) {
        std::cerr << "Error setting cipher suites" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "p3server.crt", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Error loading certificate" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "p3server.key", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Error loading private key" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "Private key does not match the certificate" << std::endl;
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void cleanup_ssl() {
    EVP_cleanup();
}

// main function with all handling
int main(int argc, char* argv[]) {
    int sockfd, new_fd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    // openssl creation
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    SSL_CTX* ssl_ctx = create_ssl_context();

    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <config_file>" << std::endl;
        return 1;
    }

    std::string port;
    std::ifstream configFile(argv[1]);
    if (!configFile.is_open()) {
        std::cerr << "Error opening configuration file: " << argv[1] << std::endl;
        return 1;
    }

    std::string line;
    while (std::getline(configFile, line)) {
        if (line.substr(0, 5) == "PORT=") {
            port = line.substr(5);
            break;
        }
    }
    configFile.close();

    if (port.empty()) {
        std::cerr << "Port number not found in configuration file!" << std::endl;
        return 1;
    }

    std::vector<Book> books;
    try {
        books = loadBooksFromFile("books.db");
        std::cout << "Loaded " << books.size() << " books from database." << std::endl;
        
        for (const auto& book : books) {
            std::cout << "ID: " << book.id 
                      << ", Title: " << book.title 
                      << ", Author: " << book.author 
                      << ", Genre: " << book.genre 
                      << ", Available: " << (book.available ? "Yes" : "No") 
                      << ", Rating: " << book.rating 
                      << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error loading books database: " << e.what() << std::endl;
        return 1;
    }

    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, port.c_str(), &hints, &servinfo)) != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            std::perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            std::perror("setsockopt");
            return 1;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            std::perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        std::cerr << "server: failed to bind\n";
        return 1;
    }

    if (listen(sockfd, BACKLOG) == -1) {
        std::perror("listen");
        return 1;
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        std::perror("sigaction");
        return 1;
    }

    std::cout << "server: waiting for connections on port " << port << " (TLS enabled)..." << std::endl;

    while (true) {
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr*)&their_addr, &sin_size);
        if (new_fd == -1) {
            std::perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr*)&their_addr), s, sizeof s);
        logConnection(s);

        if (!fork()) {
            close(sockfd);
            SSL* ssl = SSL_new(ssl_ctx);
            if (!ssl) {
                std::cerr << "Error creating SSL structure" << std::endl;
                close(new_fd);
                exit(1);
            }

            SSL_set_fd(ssl, new_fd);

            if (SSL_accept(ssl) <= 0) {
                std::cerr << "Error during SSL handshake" << std::endl;
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(new_fd);
                exit(1);
            }

            char buf[MAXDATASIZE];
            std::string currentMode = "NONE";
            bool heloReceived = false;
            std::string currentUser;
            bool awaitingPassword = false;

            while (true) {
                ssize_t numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
                if (numbytes <= 0) {
                    if (SSL_get_error(ssl, numbytes) == SSL_ERROR_ZERO_RETURN) {
                        logDisconnection(s);
                    } else {
                        std::cerr << "SSL read error" << std::endl;
                        ERR_print_errors_fp(stderr);
                    }
                    break;
                }

                buf[numbytes] = '\0';
                std::string receivedMsg(buf);
                std::string response;

                if (!heloReceived) {
                    if (receivedMsg.rfind("USER ", 0) == 0) {
                        std::string username = receivedMsg.substr(5);
                        bool userExists = false;
                        std::string userSalt;
                        std::string userHash;
                        
                        auto users = loadUsers();
                        for (const auto& user : users) {
                            if (user.username == username) {
                                userExists = true;
                                userSalt = user.salt;
                                userHash = user.passwordHash;
                                break;
                            }
                        }
                        
                        if (userExists) {
                            currentUser = username;
                            awaitingPassword = true;
                            response = formatResponse("331", "User found, password required");
                        } else {
                            // new user regis
                            std::string password = generateRandomString(PASSWORD_LENGTH, true);
                            
                            if (!isStrongPassword(password)) {
                                response = formatResponse("530", "Generated password does not meet security requirements");
                                SSL_write(ssl, response.c_str(), response.length());
                                break;
                            }
                            
                            std::string salt = generateRandomString(SALT_LENGTH);
                            std::string saltedPassword = saltPassword(password, salt);
                            std::string hash = generateHash(saltedPassword);
                            
                            User newUser{username, salt, hash};
                            saveUser(newUser);
                            
                            std::string encryptedPassword = encryptDecrypt(password, true);
                            response = formatResponse("230", "New user registered. Encrypted password: " + encryptedPassword);
                            
                            SSL_write(ssl, response.c_str(), response.length());
                            break;
                        }
                    } else if (receivedMsg.rfind("PASS ", 0) == 0 && !currentUser.empty() && awaitingPassword) {
                        std::string receivedPassword = receivedMsg.substr(5);
                        std::string password;

                        if (!isPasswordEncrypted(receivedPassword)) {
                            response = formatResponse("530", "Password must be encrypted before sending");
                            SSL_write(ssl, response.c_str(), response.length());
                            break;
                        }

                        try {
                            password = encryptDecrypt(receivedPassword, false);
                            
                            if (!isStrongPassword(password)) {
                                response = formatResponse("530", "Password does not meet security requirements");
                                SSL_write(ssl, response.c_str(), response.length());
                                break;
                            }
                        
                            auto users = loadUsers();
                            bool authSuccess = false;
                            for (const auto& user : users) {
                                if (user.username == currentUser) {
                                    std::string saltedPassword = saltPassword(password, user.salt);
                                    std::string hash = generateHash(saltedPassword);
                                    
                                    if (hash == user.passwordHash) {
                                        heloReceived = true;
                                        authSuccess = true;
                                        response = formatResponse("230", "Authentication successful");
                                    }
                                    break;
                                }
                            }
                            
                            if (!authSuccess) {
                                response = formatResponse("530", "Authentication failed");
                                currentUser.clear();
                                awaitingPassword = false;
                            }
                        } catch (const std::exception& e) {
                            response = formatResponse("530", "Error processing password");
                            SSL_write(ssl, response.c_str(), response.length());
                            break;
                        }
                    } else {
                        response = formatResponse("530", "Please login with USER command first");
                    }
                } else {
                    if (receivedMsg == "HELP") {
                        if (currentMode == "NONE") {
                            response = formatResponse("200", 
                                "Available commands:\n"
                                "SEARCH - Enter search mode\n"
                                "MANAGE - Enter management mode\n"
                                "RECOMMEND - Enter recommendation mode\n"
                                "BYE - Exit program");
                        } else if (currentMode == "SEARCH") {
                            response = formatResponse("200",
                                "Search mode commands:\n"
                                "FIND <term> - Search for books\n"
                                "DETAILS <title> - Get book details");
                        } else if (currentMode == "MANAGE") {
                            response = formatResponse("200",
                                "Management mode commands:\n"
                                "CHECKOUT <title> - Check out a book\n"
                                "RETURN <title> - Return a book\n"
                                "LIST - List available books");
                        } else if (currentMode == "RECOMMEND") {
                            response = formatResponse("200",
                                "Recommendation mode commands:\n"
                                "GET <genre> - Get recommendations\n"
                                "RATE <title> <1-5> - Rate a book");
                        }
                    } else if (receivedMsg == "SEARCH") {
                        currentMode = "SEARCH";
                        response = formatResponse("210", "Entering Search Mode");
                    } else if (receivedMsg == "MANAGE") {
                        currentMode = "MANAGE";
                        response = formatResponse("220", "Entering Management Mode");
                    } else if (receivedMsg == "RECOMMEND") {
                        currentMode = "RECOMMEND";
                        response = formatResponse("230", "Entering Recommendation Mode");
                    } else if (receivedMsg == "BYE") {
                        response = formatResponse("200", "Goodbye!");
                        SSL_write(ssl, response.c_str(), response.length());
                        break;
                    } else {
                        if (currentMode == "SEARCH") {
                            if (receivedMsg.rfind("FIND ", 0) == 0) {
                                response = findBooksByTerm(books, receivedMsg.substr(5));
                            } else if (receivedMsg.rfind("DETAILS ", 0) == 0) {
                                response = getBookDetailsById(books, receivedMsg.substr(8));
                            } else {
                                response = formatResponse("400", "Invalid search command");
                            }
                        } else if (currentMode == "MANAGE") {
                            if (receivedMsg.rfind("CHECKOUT ", 0) == 0) {
                                response = checkoutBook(receivedMsg.substr(9), books);
                            } else if (receivedMsg.rfind("RETURN ", 0) == 0) {
                                response = returnBook(receivedMsg.substr(7), books);
                            } else if (receivedMsg == "LIST") {
                                response = listAvailableBooks(books);
                            } else {
                                response = formatResponse("400", "Invalid management command");
                            }
                        } else if (currentMode == "RECOMMEND") {
                            if (receivedMsg.rfind("GET ", 0) == 0) {
                                response = recommendBooksByGenre(receivedMsg.substr(4), books);
                            } else if (receivedMsg.rfind("RATE ", 0) == 0) {
                                std::istringstream iss(receivedMsg.substr(5));
                                std::string title;
                                int rating;
                                
                                size_t lastSpace = receivedMsg.find_last_of(" ");
                                if (lastSpace != std::string::npos && lastSpace > 5) {
                                    title = receivedMsg.substr(5, lastSpace - 5);
                                    try {
                                        rating = std::stoi(receivedMsg.substr(lastSpace + 1));
                                        response = rateBook(title, rating, books);
                                    } catch (const std::invalid_argument&) {
                                        response = formatResponse("400", "Invalid rating format");
                                    }
                                } else {
                                    response = formatResponse("400", "Invalid command format");
                                }
                            } else {
                                response = formatResponse("400", "Invalid recommendation command");
                            }
                        } else {
                            response = formatResponse("400", "Please enter a mode first (SEARCH/MANAGE/RECOMMEND)");
                        }
                    }
                }

                SSL_write(ssl, response.c_str(), response.length());
            }
            
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(new_fd);
            exit(0);
        }
        close(new_fd);
    }
    
    SSL_CTX_free(ssl_ctx);
    cleanup_ssl();
    return 0;
}