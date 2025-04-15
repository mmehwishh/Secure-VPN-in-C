//Mehwish
#ifndef VPN_CONFIG_H
#define VPN_CONFIG_H

// General configuration settings
#define SERVER_PORT 443
#define BUFFER_SIZE 1024
#define MAX_PACKET_SIZE 1500

// File paths for certificates and keys
#define SERVER_CERTIFICATE "certificates/server.crt"
#define SERVER_PRIVATE_KEY "certificates/server.key"
#define CLIENT_CERTIFICATE "certificates/client.crt"
#define CLIENT_PRIVATE_KEY "certificates/client.key"
#define CA_CERTIFICATE "certificates/ca.crt"

// Paths for configuration files
#define SERVER_CONFIG_FILE "config/server_config.conf"
#define CLIENT_CONFIG_FILE "config/client_config.conf"

// Paths for log files
#define VPN_LOG_FILE "logs/vpn.log"
#define AUTH_LOG_FILE "logs/auth.log"

// Encryption settings
#define ENCRYPTION_METHOD "AES-256-CBC"
#define HMAC_DIGEST "SHA256"

// Other settings
#define MAX_CLIENTS 10
#define TIMEOUT 30 // in seconds

#endif // VPN_CONFIG_H