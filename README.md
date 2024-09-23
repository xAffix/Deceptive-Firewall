# Deceptive-Firewall

## Overview

This project simulates a **fake firewall** that mimics real-world network behaviors such as DNS query handling, OS fingerprinting, traceroute simulation, and service banner responses. It is designed to provide an environment where attackers and security professionals can test their tools and skills without interacting with actual systems.

The firewall supports dynamic responses, such as randomly generating fake IP addresses, introducing artificial delays, simulating packet loss in traceroutes, and randomizing service banners for ports like HTTP and SSH. A rate-limiting feature is also integrated to restrict access based on connection attempts.

## Why I Chose GoLang

GoLang was selected for this project due to several reasons:

- **Concurrency**: Go’s built-in support for concurrency with goroutines and channels makes it ideal for network applications that handle multiple requests simultaneously.
- **Performance**: As a statically typed compiled language, Go offers high performance, which is crucial for network applications.
- **Simplicity**: Go’s syntax is concise and easy to read, making it easier to build and maintain complex systems.
- **Networking Libraries**: Go provides excellent built-in networking libraries, simplifying the development of TCP and DNS server implementations.

## How Will This Project Be Useful

This fake firewall is useful in various scenarios:

1. **Pentesting Practice**: Security professionals can use this tool to simulate target networks and test their penetration testing tools without the risk of causing harm to live systems.
2. **Honeypots**: The fake firewall can act as a honeypot, attracting potential attackers and logging their behaviors for further analysis.
3. **Education**: It can be used by students and developers to understand how firewalls, DNS, traceroute, and other network services operate under the hood.

## How to Set Up the Firewall

### Prerequisites

Ensure you have Go installed on your machine. If not, you can install it from [here](https://golang.org/doc/install).

### Steps

1. **Clone the Repository**
    ```bash
    git clone https://github.com/xAffi/Deceptive-Firewall.git
    cd fake-firewall
    ```

2. **Prepare the Configuration File**  
   Edit the `config.json` file based on your needs. Here's an example configuration:
   
    ```json
    {
      "listen_dns": ":53",
      "listen_tcp": ":8080",
      "default_dns": "8.8.8.8",
      "os_fingerprints": {
        "192.168.1.": ["Linux 5.4", "Windows 10", "macOS Catalina"],
        "172.16.": ["Linux 4.19", "Windows 7"]
      },
      "rate_limit_period": 60,
      "rate_limit_count": 10
    }
    ```

3. **Run the Firewall**
    ```bash
    go run main.go
    ```

4. **Test It Out**  
    Use tools like `nslookup`, `dig`, or `curl` to test DNS and HTTP interactions with the fake firewall:
    ```bash
    nslookup example.com 127.0.0.1
    curl 127.0.0.1:8080
    ```

## Future Updates

Here are some planned updates to improve the functionality of this project:

- **Advanced OS Fingerprinting**: More accurate and detailed OS fingerprinting to better mimic real-world responses.
- **Enhanced Topology Simulation**: Create more complex and realistic network topologies for traceroute and path simulations.
- **Logging and Monitoring**: More robust logging to capture interactions for better analysis of intrusion attempts or network behavior.
- **Configurable Rules**: Define custom firewall rules, including IP blocking, port forwarding simulations, and more.
- **Integration with Visualization Tools**: Support for visualizing network activity, such as requests, rate limits, and service access patterns.
