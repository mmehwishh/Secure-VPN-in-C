#include <stdio.h>	
#include <stdlib.h>	
#include <string.h>	
#include <unistd.h>	
#include <sys/types.h>	
#include <sys/socket.h>	
#include <netinet/in.h>
#include <arpa/inet.h>

// Starts the VPN server, listens for clients
void start_server() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr , client_addr;
    socklen_t addr_size;
    server_sock = socket(AF_INET , SOCK_STREAM , 0);

    //bind socket
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(1194);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

    //listen for client
    listen(server_sock , 5);
    printf("VPN Server started. Listening for clients.....\n");

    while(1) {
        //Accept client connections
        addr_size = sizeof(client_addr);
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr , &addr_size);
        printf("Client connected!\n");

        //Handle client
        handle_client(client_sock);
    }
}  

// Handles incoming client requests
void handle_client(int sock) {
    
}
void authenticate_client();   // Validates username/password or certificates
void encrypt_packet();        // Encrypts outgoing data
void decrypt_packet();        // Decrypts incoming data
