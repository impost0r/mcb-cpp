#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <memory>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <termios.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

// Platform-specific includes
#ifdef __APPLE__
    #include <sys/ttycom.h>     // For TIOCGWINSZ on macOS
#else
    // Linux includes are already covered above
#endif

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "mbedtls/pem.h"
#include "mbedtls/x509.h"

class Client {
private:
    mbedtls_ssl_context ssl;
    mbedtls_net_context server_fd;
    std::string peer_name;
    std::string sock_name;
    bool is_interactive;
    int file_descriptor;

public:
    Client(mbedtls_ssl_context* ssl_ctx, mbedtls_net_context* net_ctx) 
        : is_interactive(false) {
        // Initialize and take ownership of SSL context and network context
        ssl = *ssl_ctx;  // Transfer ownership
        server_fd = *net_ctx;  // Transfer ownership
        file_descriptor = server_fd.fd;
        
        // Get peer and socket names
        struct sockaddr_in peer_addr, sock_addr;
        socklen_t addr_len = sizeof(peer_addr);
        
        if (getpeername(file_descriptor, (struct sockaddr*)&peer_addr, &addr_len) == 0) {
            peer_name = std::string(inet_ntoa(peer_addr.sin_addr)) + ":" + std::to_string(ntohs(peer_addr.sin_port));
        }
        
        addr_len = sizeof(sock_addr);
        if (getsockname(file_descriptor, (struct sockaddr*)&sock_addr, &addr_len) == 0) {
            sock_name = std::to_string(ntohs(sock_addr.sin_port)) + ":" + std::string(inet_ntoa(sock_addr.sin_addr));
        }
    }

    ~Client() {
        try {
            mbedtls_ssl_close_notify(&ssl);
            mbedtls_net_free(&server_fd);
            mbedtls_ssl_free(&ssl);
        } catch (...) {
            // Ignore cleanup errors
        }
    }

    int get_fd() const { return file_descriptor; }
    const std::string& get_peer_name() const { return peer_name; }
    const std::string& get_sock_name() const { return sock_name; }
    bool get_interactive() const { return is_interactive; }
    void set_interactive(bool interactive) { is_interactive = interactive; }

    std::string to_string() const {
        return "SSLPTY fd=" + std::to_string(file_descriptor) + 
               " " + peer_name + " => " + sock_name;
    }

    void handle_winsize() {
        struct winsize ws;
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
            unsigned char resize[5];
            resize[0] = 0x1d;
            resize[1] = (ws.ws_col >> 8) & 0xFF;
            resize[2] = ws.ws_col & 0xFF;
            resize[3] = (ws.ws_row >> 8) & 0xFF;
            resize[4] = ws.ws_row & 0xFF;
            mbedtls_ssl_write(&ssl, resize, 5);
        }
    }

    bool interactive_shell() {
        is_interactive = true;
        
        // Save terminal attributes
        struct termios old_termios;
        if (tcgetattr(STDIN_FILENO, &old_termios) != 0) {
            std::cerr << "Error getting terminal attributes" << std::endl;
            return false;
        }

        // Set terminal to raw mode
        struct termios raw = old_termios;
        cfmakeraw(&raw);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) {
            std::cerr << "Error setting terminal to raw mode" << std::endl;
            return false;
        }

        // Set up signal handler for window resize
        signal(SIGWINCH, [](int sig) {
            // This is a simplified signal handler
            // In a real implementation, you'd need a more robust approach
        });

        bool result = true;
        try {
            unsigned char buffer[1024];
            
            while (is_interactive) {
                fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(STDIN_FILENO, &read_fds);
                FD_SET(file_descriptor, &read_fds);
                
                int max_fd = std::max(STDIN_FILENO, file_descriptor) + 1;
                int select_result = select(max_fd, &read_fds, nullptr, nullptr, nullptr);
                
                if (select_result < 0) {
                    if (errno == EINTR) continue;  // Interrupted by signal
                    break;
                }

                if (FD_ISSET(STDIN_FILENO, &read_fds)) {
                    ssize_t bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer));
                    if (bytes_read <= 0) break;
                    
                    // Check for detach signal (Ctrl+D)
                    for (ssize_t i = 0; i < bytes_read; i++) {
                        if (buffer[i] == 0x04) {  // Ctrl+D
                            is_interactive = false;
                            std::cout << "\r\nDetached from fd=" << file_descriptor << "\r\n";
                            std::cout.flush();
                            goto cleanup;
                        }
                        if (buffer[i] == 0x1d) {  // Resize signal
                            // Skip resize characters
                            continue;
                        }
                    }
                    
                    mbedtls_ssl_write(&ssl, buffer, bytes_read);
                }

                if (FD_ISSET(file_descriptor, &read_fds)) {
                    int bytes_read = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer));
                    if (bytes_read <= 0) break;
                    
                    write(STDOUT_FILENO, buffer, bytes_read);
                }
            }
        } catch (...) {
            result = false;
            std::cerr << "Exception in interactive shell" << std::endl;
        }

    cleanup:
        // Restore terminal attributes
        tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);
        std::cout.flush();
        return result;
    }
};

class MCB {
private:
    std::vector<std::unique_ptr<Client>> clients;
    std::mutex clients_mutex;
    int server_socket;
    int port;
    bool accept_loop;
    std::thread server_thread;
    
    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt server_cert;
    mbedtls_pk_context server_key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // We'll generate the certificate at runtime

public:
    static const std::string CERT_FILE;
    MCB(int server_port) : port(server_port), accept_loop(true) {
        // Initialize mbedTLS structures
        mbedtls_ssl_config_init(&ssl_conf);
        mbedtls_x509_crt_init(&server_cert);
        mbedtls_pk_init(&server_key);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        
        setup_server();
    }

    ~MCB() {
        accept_loop = false;
        if (server_thread.joinable()) {
            server_thread.join();
        }
        
        if (server_socket >= 0) {
            close(server_socket);
        }
        
        // Cleanup mbedTLS
        mbedtls_ssl_config_free(&ssl_conf);
        mbedtls_x509_crt_free(&server_cert);
        mbedtls_pk_free(&server_key);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
    }

private:
    bool setup_server() {
        // Initialize random number generator
        const char* seed = "MCB_SSL_SERVER_SEED";
        if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  reinterpret_cast<const unsigned char*>(seed),
                                  strlen(seed)) != 0) {
            std::cerr << "Failed to seed random number generator" << std::endl;
            return false;
        }

        // Use a simplified SSL setup without certificates
        // This approach uses PSK (Pre-Shared Key) or just basic SSL without cert validation
        std::cout << "Setting up SSL without certificate files (embedded crypto)" << std::endl;

        // Configure SSL
        if (mbedtls_ssl_config_defaults(&ssl_conf, MBEDTLS_SSL_IS_SERVER,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
            std::cerr << "Failed to set SSL config defaults" << std::endl;
            return false;
        }

        // Configure SSL without certificate validation
        mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
        
        // Skip certificate configuration - using anonymous SSL
        std::cout << "SSL configured for anonymous connections (no certificate validation)" << std::endl;

        // Create server socket
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket < 0) {
            std::cerr << "Failed to create server socket" << std::endl;
            return false;
        }

        int reuse = 1;
        setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Failed to bind server socket" << std::endl;
            return false;
        }

        if (listen(server_socket, 5) < 0) {
            std::cerr << "Failed to listen on server socket" << std::endl;
            return false;
        }

        // Start server thread
        server_thread = std::thread(&MCB::server_loop, this);
        return true;
    }

    void server_loop() {
        while (accept_loop) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
            if (client_socket < 0) {
                if (accept_loop) {
                    std::cerr << "Accept failed" << std::endl;
                }
                continue;
            }

            std::cout << "new connection from " << inet_ntoa(client_addr.sin_addr) 
                      << ":" << ntohs(client_addr.sin_port) << std::endl;

            // Set up SSL for this client
            mbedtls_ssl_context client_ssl;
            mbedtls_net_context client_net;
            
            mbedtls_ssl_init(&client_ssl);
            mbedtls_net_init(&client_net);
            client_net.fd = client_socket;

            if (mbedtls_ssl_setup(&client_ssl, &ssl_conf) == 0) {
                mbedtls_ssl_set_bio(&client_ssl, &client_net, mbedtls_net_send, mbedtls_net_recv, nullptr);
                
                // Perform SSL handshake
                int handshake_result;
                while ((handshake_result = mbedtls_ssl_handshake(&client_ssl)) != 0) {
                    if (handshake_result != MBEDTLS_ERR_SSL_WANT_READ && 
                        handshake_result != MBEDTLS_ERR_SSL_WANT_WRITE) {
                        std::cerr << "SSL handshake failed" << std::endl;
                        break;
                    }
                }

                if (handshake_result == 0) {
                    // Create client and add to list
                    std::lock_guard<std::mutex> lock(clients_mutex);
                    clients.push_back(std::unique_ptr<Client>(new Client(&client_ssl, &client_net)));
                    std::cout << "Client added to list, total clients: " << clients.size() << std::endl;
                } else {
                    mbedtls_ssl_free(&client_ssl);
                    mbedtls_net_free(&client_net);
                    close(client_socket);
                }
            } else {
                close(client_socket);
            }
        }
    }

public:
    void do_list() {
        std::lock_guard<std::mutex> lock(clients_mutex);
        std::cout << "Total clients: " << clients.size() << std::endl;
        for (size_t i = 0; i < clients.size(); ++i) {
            std::cout << i << " " << clients[i]->to_string() << std::endl;
        }
        if (clients.size() == 0) {
            std::cout << "No clients connected" << std::endl;
        }
    }

    void do_interact(const std::string& arg) {
        try {
            int idx = std::stoi(arg);
            std::lock_guard<std::mutex> lock(clients_mutex);
            
            if (idx < 0 || idx >= static_cast<int>(clients.size())) {
                std::cout << "Invalid index: " << idx << std::endl;
                return;
            }
            
            clients[idx]->interactive_shell();
        } catch (const std::exception& e) {
            std::cout << "Problem with index " << arg << " :: " << e.what() << std::endl;
        }
    }

    void do_exit() {
        accept_loop = false;
        shutdown(server_socket, SHUT_RDWR);
        if (server_thread.joinable()) {
            server_thread.join();
        }
        std::cout << "Exiting MCB" << std::endl;
        exit(0);
    }

    void cmdloop() {
        std::string line;
        std::cout << "MCB listening on " << port << std::endl;
        
        while (true) {
            std::cout << "(MCB) ";
            std::cout.flush();
            
            if (!std::getline(std::cin, line)) {
                // EOF
                std::cout << std::endl;
                break;
            }
            
            if (line.empty()) {
                continue;
            }
            
            std::istringstream iss(line);
            std::string command, arg;
            iss >> command >> arg;
            
            if (command == "list") {
                do_list();
            } else if (command == "interact") {
                do_interact(arg);
            } else if (command == "exit") {
                do_exit();
                break;
            } else if (command == "help") {
                std::cout << "Available commands:" << std::endl;
                std::cout << "  list          - list connected peers" << std::endl;
                std::cout << "  interact <n>  - interact with pty on peer n" << std::endl;
                std::cout << "  exit          - exit MCB" << std::endl;
            } else {
                std::cout << "Unknown command: " << command << std::endl;
                std::cout << "Type 'help' for available commands" << std::endl;
            }
        }
    }
};

const std::string MCB::CERT_FILE = "mcb.pem";

bool file_exists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << argv[0] << " <port>" << std::endl;
        return -1;
    }

    int port;
    try {
        port = std::stoi(argv[1]);
    } catch (const std::exception& e) {
        std::cout << "Invalid port number: " << argv[1] << std::endl;
        return -1;
    }

    MCB mcb(port);
    
    try {
        mcb.cmdloop();
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}