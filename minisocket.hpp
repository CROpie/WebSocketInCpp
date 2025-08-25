#pragma once

#include <string>
#include <vector>
#include <functional> // std::function
#include <iostream> // runtime_error
#include <sstream> // ostringstream

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h> // needed for addrinfo
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h> // socket()
#include <openssl/sha.h>

#define BACKLOG 10

namespace minisocket {

// ---- Minimal base64 encoder (sufficient for handshake) ----
inline std::string base64_encode(const unsigned char *data, size_t len) {
    static const char *tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((len+2)/3*4);
    for (size_t i=0;i<len;i+=3) {
        int val = (data[i] << 16) +
                  ((i+1<len)?(data[i+1]<<8):0) +
                  ((i+2<len)?(data[i+2]):0);
        out.push_back(tbl[(val>>18)&0x3F]);
        out.push_back(tbl[(val>>12)&0x3F]);
        out.push_back((i+1<len)?tbl[(val>>6)&0x3F]:'=');
        out.push_back((i+2<len)?tbl[(val)&0x3F]:'=');
    }
    return out;
}

class Server {
    public:
        using MessageHandler = std::function<void(int client, const std::string&)>;

        void start(const char* port, MessageHandler handler) {
            // --- MAKE CONNECTION ---
            running = true;
            this->handler = handler;
            int yes = 1;

            struct addrinfo hints{}, *res;
            hints.ai_family = AF_UNSPEC; // use IPv4 or IPv6, whichever
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = AI_PASSIVE; // for binding (fill in IP for me)

            // load up address structs
            // NULL will bind all local IP addresses (0,0,0,0)
            int status = getaddrinfo(NULL, port, &hints, &res);
            // int status = getaddrinfo("127.0.0.1", port, &hints, &res);
            if (status != 0) throw std::runtime_error("getaddrinfo error");

            // make a socket
            int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (sockfd == -1) throw std::runtime_error("socket error");

            // allow other sockets to bind() to this port
            // (get around address already in use error messages when try to restart server after a crash)
            setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

            // bind it to the port we passed in to getaddrinfo
            int bindRes = bind(sockfd, res->ai_addr, res->ai_addrlen);
            if (bindRes == -1) throw std::runtime_error("bind error");

            // begin listening, allow max 10 connections in incoming queue
            listen(sockfd, BACKLOG);

            struct sockaddr_storage their_addr;
            socklen_t addr_size;

            addr_size = sizeof their_addr;
            int incfd = accept(sockfd, (struct sockaddr *)&their_addr, 
            &addr_size);
            if (incfd == -1)  throw std::runtime_error("accept error");

            char buffer[1024];
            std::string incoming;

            while (incoming.find("\r\n\r\n") == std::string::npos) {
                int n = recv(incfd, buffer, sizeof(buffer), 0);
                if (n <= 0) throw std::runtime_error("connection closed before handshake complete");
                incoming.append(buffer, n);
            }

            // std::cout << "incoming: " << incoming << std::endl;

            // --- HTTP Upgrade (handshake) ---
            auto key_pos = incoming.find("Sec-WebSocket-Key:");
            if (key_pos==std::string::npos) { 
                close(incfd);
                throw std::runtime_error("cannot find sec-websocket-key");
            }
            auto line_end = incoming.find("\r\n", key_pos);
            std::string key = incoming.substr(key_pos+19, line_end-key_pos-19);

            // trim leading spaces
            while (!key.empty() && (key.front() == ' ')) key.erase(0, 1);

            // trim trailing spaces
            while (!key.empty() && (key.back() == ' ')) key.pop_back();

            // this string is a constant for websockets
            std::string accept_src = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

            // accept_src = key + GUID
            unsigned char hash[SHA_DIGEST_LENGTH];
            SHA1(reinterpret_cast<const unsigned char*>(accept_src.c_str()), accept_src.size(), hash);
            std::string accept_key = base64_encode(hash, SHA_DIGEST_LENGTH);

            std::ostringstream resp;
            resp << "HTTP/1.1 101 Switching Protocols\r\n"
                << "Upgrade: websocket\r\n"
                << "Connection: Upgrade\r\n"
                << "Sec-WebSocket-Accept: " << accept_key << "\r\n\r\n";

            // std::cout << "response: " << resp.str() << std::endl;

            send(incfd, resp.str().c_str(), resp.str().size(), 0);

            // Frame Loop
            while (running) {

                // recv has an internal buffer. The multiple calls are pulling data out of this buffer. It does not 'call' the client
                /*
                1: First 2 bytes -> base header
                2: Next 2 or 8 bytes -> extended length (if needed)
                3: Next 4 bytes -> masking key (if present)
                4: Remaining N bytes -> payload
                */

                // read the WebSocket frame header
                unsigned char hdr[2];
                int flagsRecv = recv(incfd, hdr, 2, MSG_WAITALL);
                if (flagsRecv <= 0) break;

                // hdr[0]: flags (FIN, opcode)

                // hdr[1]: masking bit + length info
                // Bit 0: tells if frame is masked. 1: masked, 0:unmasked
                // Bit 1-7: If 0-125 -> payload length. If 126 next 2 bits are payload length. If 127 next 8 bytes are payload length.
                // & 0x80 = 10000000 in binary, extracts the mask bit
                // & 0x7F = 01111111 in binary, extracts the 7-bit payload length
                bool masked = hdr[1] & 0x80;       // client → server frames are always masked
                uint64_t len = hdr[1] & 0x7F;      // payload length (7 bits)

                if (len==126) {
                    unsigned char ext[2];
                    recv(incfd, ext, 2, MSG_WAITALL);
                    len = (ext[0]<<8) | ext[1];
                } else if (len==127) {
                    unsigned char ext[8];
                    recv(incfd, ext, 8, MSG_WAITALL);
                    len=0;
                    for (int i=0; i<8; ++i) len=(len<<8)|ext[i];
                }

                // client-to-server frames are always masked
                // reads 4-byte masking key
                unsigned char mask[4];
                if (masked) recv(incfd, mask, 4, MSG_WAITALL);

                // reads payload data from the socket (in masked form - if coming from browser)
                std::string payload(len,'\0'); 
                int payloadRecv = recv(incfd, &payload[0], len, MSG_WAITALL);
                if (payloadRecv <= 0) break;

                // unmask the payload
                // apply XOR with the mask to get the real message
                if (masked) for (size_t i=0; i<len; ++i) payload[i]^=mask[i%4];
        
                // close frame -> exit loop
                if (hdr[0]==0x88) break; // close frame

                // 0x81 = FIN + opcode 0x1 (text frame)
                // call handler with the decoded string
                if (hdr[0]==0x81 && handler) handler(incfd, payload);
            }
            close(incfd);
        }

        void sendFrame(int client, const std::string& msg) {
            std::string frame;
            frame.push_back(0x81); // FIN + text

            if (msg.size() <= 125) {
                frame.push_back((char)msg.size());
            } else if (msg.size() < 65536) {
                frame.push_back(126);
                frame.push_back((msg.size()>>8)&0xFF);
                frame.push_back(msg.size()&0xFF);
            } else {
                frame.push_back(127);
                for (int i=7;i>=0;--i) frame.push_back((msg.size()>>(8*i))&0xFF);
            }
            frame += msg;
            send(client, frame.data(), frame.size(), 0);
        }

        void stop() {
            running = false;
            if (listen_fd >= 0) close(listen_fd);
        }

    private:
        bool running{false};
        int listen_fd = -1;
        MessageHandler handler;

};
} // namespace minisocket