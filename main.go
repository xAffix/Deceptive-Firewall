package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
)

type FakeFirewall struct {
	DNSResponses    map[string]string
	OSFingerprints  map[string][]string // Map IP ranges to OS fingerprints
	FakeTopology    map[string][]string
	ServiceBanners  map[int][]string
	Config          *Configuration
	ConnectionCount map[string]int
	mu              sync.RWMutex
}

type Configuration struct {
	ListenDNS       string              `json:"listen_dns"`
	ListenTCP       string              `json:"listen_tcp"`
	DefaultDNS      string              `json:"default_dns"`
	OSFingerprints  map[string][]string `json:"os_fingerprints"`
	RateLimitPeriod int                 `json:"rate_limit_period"`
	RateLimitCount  int                 `json:"rate_limit_count"`
}

func NewFakeFirewall(configPath string) (*FakeFirewall, error) {
	config, err := loadConfiguration(configPath)
	if err != nil {
		return nil, err
	}

	fw := &FakeFirewall{
		DNSResponses:    make(map[string]string),
		OSFingerprints:  config.OSFingerprints,
		FakeTopology:    make(map[string][]string),
		ServiceBanners:  make(map[int][]string),
		Config:          config,
		ConnectionCount: make(map[string]int),
	}

	go fw.watchConfig(configPath)

	return fw, nil
}

func loadConfiguration(file string) (*Configuration, error) {
	var config Configuration
	configFile, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer configFile.Close()

	jsonParser := json.NewDecoder(configFile)
	err = jsonParser.Decode(&config)
	return &config, err
}

func (fw *FakeFirewall) watchConfig(configPath string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Println("Config file modified. Reloading...")
					newConfig, err := loadConfiguration(configPath)
					if err != nil {
						log.Println("Error reloading config:", err)
					} else {
						fw.mu.Lock()
						fw.Config = newConfig
						fw.OSFingerprints = newConfig.OSFingerprints
						fw.mu.Unlock()
						log.Println("Config reloaded successfully")
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("Error watching config file:", err)
			}
		}
	}()

	err = watcher.Add(configPath)
	if err != nil {
		log.Fatal(err)
	}
	<-done
}

func (fw *FakeFirewall) HandleDNSQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("DNS query: %s\n", q.Name)
			ip := fw.DNSResponses[q.Name]
			if ip == "" {
				ip = fw.generateRandomIP()
			}
			rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
			log.Printf("DNS response: %s -> %s\n", q.Name, ip)
		}
	}
}

func (fw *FakeFirewall) generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255))
}

func (fw *FakeFirewall) HandleOSFingerprint(ip string) string {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	for ipRange, fingerprints := range fw.OSFingerprints {
		if isIPInRange(ip, ipRange) {
			return fingerprints[rand.Intn(len(fingerprints))]
		}
	}
	return "Unknown OS"
}

func isIPInRange(ip, ipRange string) bool {
	// Implement IP range checking logic here
	// For simplicity, we're just doing a prefix match
	return strings.HasPrefix(ip, ipRange)
}

func (fw *FakeFirewall) HandleTraceroute(destination string) []string {
	log.Printf("Traceroute simulation requested for %s\n", destination)
	if rand.Float32() < 0.3 {
		log.Printf("Simulating packet loss for traceroute to %s\n", destination)
		return []string{}
	}
	if route, exists := fw.FakeTopology[destination]; exists {
		log.Printf("Using predefined route for traceroute to %s: %v\n", destination, route)
		return route
	}
	// Generate a random fake route
	route := []string{}
	for i := 0; i < rand.Intn(5)+3; i++ {
		route = append(route, fw.generateRandomIP())
	}
	log.Printf("Generated random route for traceroute to %s: %v\n", destination, route)
	return route
}

func main() {
	rand.Seed(time.Now().UnixNano())
	
	fw, err := NewFakeFirewall("config.json")
	if err != nil {
		log.Fatal("Error loading configuration:", err)
	}

	// Example setup
	fw.DNSResponses["example.com."] = "203.0.113.0"
	fw.FakeTopology["8.8.8.8"] = []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "8.8.8.8"}
	fw.ServiceBanners[22] = []string{"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"}
	fw.ServiceBanners[80] = []string{"Apache/2.4.25 (Debian)", "nginx/1.14.0 (Ubuntu)", "Microsoft-IIS/10.0"}

	go fw.listenDNS()
	go fw.listenTCP()

	select {}
}

func (fw *FakeFirewall) listenDNS() {
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		fw.HandleDNSQuery(m)
		w.WriteMsg(m)
	})

	log.Printf("Starting DNS server on %s\n", fw.Config.ListenDNS)
	server := &dns.Server{Addr: fw.Config.ListenDNS, Net: "udp"}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start DNS server: %s\n", err.Error())
	}
}

func (fw *FakeFirewall) listenTCP() {
	listener, err := net.Listen("tcp", fw.Config.ListenTCP)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Printf("Starting TCP listener on %s\n", fw.Config.ListenTCP)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go fw.handleTCPConnection(conn)
	}
}

func (fw *FakeFirewall) handleTCPConnection(conn net.Conn) {
	defer conn.Close()
	
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	
	if !fw.checkRateLimit(remoteAddr.IP.String()) {
		log.Printf("Rate limit exceeded for %s\n", remoteAddr.IP)
		return
	}
	
	log.Printf("TCP connection from %s on port %d\n", remoteAddr.IP, localAddr.Port)
	
	// Introduce artificial delay
	time.Sleep(time.Duration(rand.Intn(3000)) * time.Millisecond)
	
	osFingerprint := fw.HandleOSFingerprint(remoteAddr.IP.String())
	
	banners, exists := fw.ServiceBanners[localAddr.Port]
	if exists && len(banners) > 0 {
		banner := banners[rand.Intn(len(banners))]
		fmt.Fprintf(conn, "%s\r\n", banner)
		log.Printf("Sent banner to %s: %s\n", remoteAddr.IP, banner)
	} else {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nServer: %s\r\n\r\n", osFingerprint)
		log.Printf("Sent HTTP response to %s with OS fingerprint: %s\n", remoteAddr.IP, osFingerprint)
	}
}

func (fw *FakeFirewall) checkRateLimit(ip string) bool {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	
	now := time.Now().Unix()
	if count, exists := fw.ConnectionCount[ip]; exists {
		if count >= fw.Config.RateLimitCount {
			return false
		}
	}
	fw.ConnectionCount[ip]++
	go func() {
		time.Sleep(time.Duration(fw.Config.RateLimitPeriod) * time.Second)
		fw.mu.Lock()
		fw.ConnectionCount[ip]--
		fw.mu.Unlock()
	}()
	return true
}
