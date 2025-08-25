#include "minisocket.hpp"

minisocket::Server server;

void onMessage(int client, const std::string& msg) {
    std::cout << "Received from client " << client << ": " << msg << "\n";
    // You could echo back or process the message here
    server.sendFrame(client, "This is some text");
}

int main() {

    server.start("9002", &onMessage);
    return 0;
}

// g++ main.cpp -o server
