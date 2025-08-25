#include "minisocket.hpp"

minisocket::Server server;

void onMessage(int client, const std::string& msg) {
    std::cout << "Received from client " << client << ": " << msg << "\n";
    // You could echo back or process the message here
    server.sendFrame(client, "This is some text");
}

int main() {

    server.init("9002", &onMessage, true);
    server.run();
    return 0;
}

// g++ main.cpp -o server
