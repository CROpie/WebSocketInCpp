/*

    Minimal server-side websocket implementation using threads to handle multiple clients
    Version: 1.1.0
    Requires -lcrypto
    https://github.com/CROpie/WebSocketInCpp

*/

#pragma once

#include <string>
#include <vector>
#include <thread>
#include <fstream>
#include <functional> // std::function
#include <iostream> // runtime_error
#include <sstream> // ostringstream
#include <sys/types.h> // size_t (probably redundant)
#include <sys/socket.h> // socket(), bind(), accept(), recv(), send()
#include <netdb.h> // needed for getaddrinfo()
#include <netinet/in.h> // sockaddr_in
#include <unistd.h> // close()
#include <openssl/sha.h> // SHA1()

// updateAll
#include <mutex>
#include <set>

#define BACKLOG 10

namespace minisocket {

class Server {
    private:
    int socket_fd{-1};
    bool isRunning{false};
    bool isDebug{true};

    std::mutex clients_mutex;
    std::set<int> clients;

    struct Frame {
        bool fin;
        uint8_t opcode;
        bool masked;
        uint64_t length;
        unsigned char mask[4];
        std::string payload;
    };

    public:
        std::function<void(int client_fd, const std::string& payload)> on_message;
        std::function<void(int)> on_disconnect;

        /*
            Function made up of the following:
                getaddrinfo() - figure out the IP/port to bind
                socket() - create the listening socket
                setsockopt() - modify with options, eg: allow other sockets to bind to this port
                bind() - attach the socket to the port
                listen() - mark as a passive socket ready to accept connections
        */
        void init(const char* port) {

            struct addrinfo hints{}, *res;
            hints.ai_family = AF_UNSPEC; // use IPv4 or IPv6, whichever
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = AI_PASSIVE; // for binding (fill in IP for me)

            // load up address structs
            // NULL will bind all local IP addresses (0,0,0,0)
            if (getaddrinfo(NULL, port, &hints, &res) != 0) {
                throw std::runtime_error("getaddrinfo error");
            };

            // make a socket
            socket_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (socket_fd == -1) throw std::runtime_error("socket error");

            // allow other sockets to bind() to this port
            // (get around address already in use error messages when try to restart server after a crash)
            int yes = 1;
            setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

            // bind it to the port we passed in to getaddrinfo
            if (bind(socket_fd, res->ai_addr, res->ai_addrlen) == -1) {
                throw std::runtime_error("bind error");
            }

            // begin listening, allow max 10 connections in incoming queue
            listen(socket_fd, BACKLOG);
        }

        std::ostringstream generateHandshakeResponse(int client_fd, std::string incoming) {
            // --- HTTP Upgrade (handshake) ---
            auto key_pos = incoming.find("Sec-WebSocket-Key:");
            if (key_pos==std::string::npos) { 
                close(client_fd);
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

            return resp;
        }

        /*
            accept() [blocking] - check for new clients
            perform handshake
            => client_fd
        */
        int accept_new_client() {
            struct sockaddr_storage their_addr;
            socklen_t addr_size = sizeof their_addr;

            int client_fd = accept(socket_fd, (struct sockaddr *)&their_addr, &addr_size);

            if (client_fd == -1)  throw std::runtime_error("accept error");

            char buffer[1024];
            std::string incoming;

            while (incoming.find("\r\n\r\n") == std::string::npos) {
                int n = recv(client_fd, buffer, sizeof(buffer), 0);
                if (n <= 0) throw std::runtime_error("connection closed before handshake complete");
                incoming.append(buffer, n);
            }

            std::ostringstream resp = generateHandshakeResponse(client_fd, incoming);

            send(client_fd, resp.str().c_str(), resp.str().size(), 0);

            std::cout << "client_fd: " << client_fd << std::endl;

            return client_fd;
        }

        // Extract header from recv stream, insert values into Frame struct. determine the payload length from header
        bool read_header(int client_fd, Frame& frame) {
            // read first 2 bytes of recv stream which is the WebSocket frame header
            // Byte 0 (hdr[0]): FIN | RSV1 | RSV2 | RSV3 | OPCODE (1 | 1 | 1 | 1 | 4 bits)
            // Byte 1 (hdr[1]): MASK | Payload length (1 | 7 bits)
            unsigned char hdr[2];

            if (recv(client_fd, hdr, 2, MSG_WAITALL) <= 0) return false;

            frame.fin = hdr[0] & 0x80; // 1000 0000 => check FIN bit. 1: final frame. 0: more frames are coming.
            frame.opcode = hdr[0] & 0x0F; // 0000 1111 => extract opcode

            frame.masked = hdr[1] & 0x80; // 1000 0000 => check MASK: 1: client-> server
            frame.length = hdr[1] & 0x7F; // 0111 1111 => get payload length


            // Bit 1-7: If 0-125 -> payload length. If 126 next 2 bits are payload length. If 127 next 8 bytes are payload length.
            if (frame.length == 126) {
                unsigned char ext[2];
                if (recv(client_fd, ext, 2, MSG_WAITALL) <= 0) return false;
                frame.length = (ext[0] << 8) | ext[1];
            } else if (frame.length == 127) {
                unsigned char ext[8];
                if (recv(client_fd, ext, 8, MSG_WAITALL) <= 0) return false;
                frame.length = 0;
                for (int i = 0; i < 8; ++i) frame.length = (frame.length << 8) | ext[i];
            }
            return true;
        }

        // Pull masking key out of the recv stream (if it exists)
        bool read_mask(int client_fd, Frame& frame) {
            if (frame.masked) {
                if (recv(client_fd, frame.mask, 4, MSG_WAITALL) <= 0) return false;
            }
            return true;
        }

        bool read_payload(int client_fd, Frame& frame) {
            frame.payload.resize(frame.length);

            // reads payload data from the socket in masked form
            if (recv(client_fd, &frame.payload[0], frame.length, MSG_WAITALL) <= 0) return false;


            // unmask the payload by applying XOR with the mask to get the real message
            if (frame.masked) {
                for (size_t i = 0; i < frame.length; ++i) {
                    frame.payload[i] ^= frame.mask[i % 4];
                }
            }
            return true;

        }

        /*
            per thread:
                in a loop (until browser window closes):
                    recv() [blocking] - wait for a message (payload) from the client
                    pull the payload from recv stream
                    send to function created by user of minisocket so they can choose what to do with it
        */
        void handle_client(int client_fd) {

            Frame frame;
            
            while (true) {
                /*
                    recv has an internal buffer. The multiple recv calls are pulling data out of this buffer.
                    It does not 'call' the client each time

                    1: First 2 bytes -> base header
                    2: Next 2 or 8 bytes -> extended length (if needed)
                    3: Next 4 bytes -> masking key (if present)
                    4: Remaining N bytes -> payload
                */
               if (!read_header(client_fd, frame)) break;
               if (!read_mask(client_fd, frame)) break;
               if (!read_payload(client_fd, frame)) break;

                // close frame -> exit loop
               if (frame.opcode == 0x8) break;

                // text frame -> call handler function (if it has been passed in to minisocket)
               if (frame.opcode == 0x1) {
                if (on_message) on_message(client_fd, frame.payload);
               }
            }

            // out of the loop means socket connection has broken (intentional or otherwise)
            // if a disconnect function is passed in by the user of minisocket, run it
            if (on_disconnect) on_disconnect(client_fd);
            remove_client(client_fd);
            close(client_fd);
        }

        /*
            to be used in the (user-created) handler function
            translate string to be ready to be sent via sockets
            sendFrameToAll() to be used for global updates
            send()
        */
        std::string generateFrame(const std::string& msg) {
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
            return frame;
        }

        void sendFrame(int client_fd, const std::string& msg) {
            std::string frame = generateFrame(msg);
            send(client_fd, frame.data(), frame.size(), 0);
        }

        void sendFrameToAll(const std::string& msg) {
            std::string frame = generateFrame(msg);
            for (int client_fd : clients) {
                send(client_fd, frame.data(), frame.size(), 0);
            }
        }

        void stop() {
            isRunning = false;
            if (socket_fd >= 0) close(socket_fd);
        }

        // mutex: mutual exclusion. Ensure only one thread at a time can access a resource
        void add_client(int client_fd) {
            std::lock_guard<std::mutex> lock(clients_mutex);
            clients.insert(client_fd);
        }

        void remove_client(int client_fd) {
            std::lock_guard<std::mutex> lock(clients_mutex);
            clients.erase(client_fd);
        }

        /*
            main loop
                run accept_new_client(), which will block at 'accept' until a connection is made
                after that connection is made, it will spawn a new thread to run handle_client()
                handle_client() runs in a loop, which will block at 'recv' until data is sent
                closing the browser window will return from handle_client and detach that thread
        */
        void run() {
            isRunning = true;
            while (isRunning) {
                int client_fd = accept_new_client();
                add_client(client_fd);
                std::thread([this, client_fd]() {
                    handle_client(client_fd);
                }).detach();
            }
        }

        // ---- Minimal base64 encoder (sufficient for handshake) ----
        std::string base64_encode(const unsigned char *data, size_t len) {
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


};
} // namespace minisocket