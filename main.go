package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"io"


	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
	"github.com/apparentlymart/go-cidr/cidr"
)

type FakeFirewall struct {
	DNSResponses    map[string]string
	OSFingerprints  map[string][]string
	FakeTopology    map[string][]string
	ServiceBanners  map[int][]string
	FTPResponses    map[string]string
	Config          *Configuration
	ConnectionCount map[string]int
	KnownBadIPs     map[string]bool
	mu              sync.RWMutex
	dnsServer       *dns.Server
	tcpListener     net.Listener
	ftpListener     net.Listener
}

type Configuration struct {
	ListenDNS       string              `json:"listen_dns"`
	ListenTCP       string              `json:"listen_tcp"`
	ListenFTP       string              `json:"listen_ftp"`
	DefaultDNS      string              `json:"default_dns"`
	OSFingerprints  map[string][]string `json:"os_fingerprints"`
	RateLimitPeriod int                 `json:"rate_limit_period"`
	RateLimitCount  int                 `json:"rate_limit_count"`
	HoneypotIP      string              `json:"honeypot_ip"`
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
		FTPResponses:    make(map[string]string),
		Config:          config,
		ConnectionCount: make(map[string]int),
		KnownBadIPs:     make(map[string]bool),
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
					if err := fw.ReloadConfig(configPath); err != nil {
						log.Println("Error reloading config:", err)
					} else {
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

func (fw *FakeFirewall) ReloadConfig(configPath string) error {
	newConfig, err := loadConfiguration(configPath)
	if err != nil {
		return err
	}

	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.Config = newConfig
	fw.OSFingerprints = newConfig.OSFingerprints
	// Add any other fields that should be updated here

	return nil
}

func (fw *FakeFirewall) HandleDNSQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			ip := fw.DNSResponses[q.Name]
			if ip == "" {
				ip = fw.generateRandomIP()
			}
			rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
			log.Printf("DNS query: %s -> %s\n", q.Name, ip)
		default:    
			log.Printf("Unhandled DNS query type: %d for %s", q.Qtype, q.Name)
		}
	}
}

func (fw *FakeFirewall) generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(254)+1, rand.Intn(254)+1, rand.Intn(254)+1, rand.Intn(254)+1)
}

func (fw *FakeFirewall) HandleOSFingerprint(ip string) string {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	for ipRange, fingerprints := range fw.OSFingerprints {
		if fw.isIPInRange(ip, ipRange) {
			return fingerprints[rand.Intn(len(fingerprints))]
		}
	}
	return "Unknown OS"
}

func (fw *FakeFirewall) isIPInRange(ip, ipRange string) bool {
	_, network, err := net.ParseCIDR(ipRange)
	if err != nil {
		return strings.HasPrefix(ip, ipRange)
	}
	return network.Contains(net.ParseIP(ip))
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

	// Setup example
	fw.DNSResponses["example.com."] = "203.0.113.0"
	fw.FakeTopology["8.8.8.8"] = []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "8.8.8.8"}
	fw.ServiceBanners[22] = []string{"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"}
	fw.ServiceBanners[80] = []string{"Apache/2.4.25 (Debian)", "nginx/1.14.0 (Ubuntu)", "Microsoft-IIS/10.0"}
	fw.FTPResponses = map[string]string{
		"USER": "331 Please specify the password.\r\n",
		"PASS": "230 Login successful.\r\n",
		"SYST": "215 UNIX Type: L8\r\n",
		"PWD":  "257 \"/\" is the current directory\r\n",
		"TYPE": "200 Switching to Binary mode.\r\n",
		"QUIT": "221 Goodbye.\r\n",
	}

	fw.startServers()
	fw.handleSignals()

	select {}
}

func (fw *FakeFirewall) startServers() {
	go fw.listenDNS()
	go fw.listenTCP()
	go fw.listenFTP()
}

func (fw *FakeFirewall) handleSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fw.shutdown()
		os.Exit(0)
	}()
}

func (fw *FakeFirewall) shutdown() {
	log.Println("Shutting down servers...")
	if fw.dnsServer != nil {
		if err := fw.dnsServer.Shutdown(); err != nil {
			log.Printf("Error shutting down DNS server: %v\n", err)
		}
	}
	if fw.tcpListener != nil {
		log.Println("Closing TCP listener...")
		if err := fw.tcpListener.Close(); err != nil {
			log.Printf("Error closing TCP listener: %v\n", err)
		}
	}
	if fw.ftpListener != nil {
		log.Println("Closing FTP listener...")
		if err := fw.ftpListener.Close(); err != nil {
			log.Printf("Error closing FTP listener: %v\n", err)
		}
	}
}


func (fw *FakeFirewall) listenDNS() {
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		fw.HandleDNSQuery(m)
		w.WriteMsg(m)
	})

	log.Printf("Starting DNS server on %s\n", fw.Config.ListenDNS)
	fw.dnsServer = &dns.Server{Addr: fw.Config.ListenDNS, Net: "udp"}
	err := fw.dnsServer.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start DNS server: %s\n", err.Error())
	}
}

func (fw *FakeFirewall) listenTCP() {
	var err error
	fw.tcpListener, err = net.Listen("tcp", fw.Config.ListenTCP)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting TCP listener on %s\n", fw.Config.ListenTCP)
	for {
		conn, err := fw.tcpListener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			break
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
	
	fw.mu.RLock()
	if fw.KnownBadIPs[remoteAddr.IP.String()] {
    fw.mu.RUnlock()
    log.Printf("Redirecting known bad IP %s to honeypot\n", remoteAddr.IP)
    fw.redirectToHoneypot(conn)
    return
	}

	fw.mu.RUnlock()
	
	log.Printf("TCP connection from %s on port %d\n", remoteAddr.IP, localAddr.Port)
	
	time.Sleep(time.Duration(rand.Intn(300)) * time.Millisecond)
	
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

func (fw *FakeFirewall) redirectToHoneypot(conn net.Conn) {
	honeypotConn, err := net.Dial("tcp", fw.Config.HoneypotIP)
	if err != nil {
		log.Printf("Failed to connect to honeypot: %v\n", err)
		return
	}
	defer honeypotConn.Close()

	go func() {
		_, err := io.Copy(honeypotConn, conn)
		if err != nil {
			log.Printf("Error copying to honeypot: %v\n", err)
		}
	}()

	_, err = io.Copy(conn, honeypotConn)
	if err != nil {
		log.Printf("Error copying from honeypot: %v\n", err)
	}
}

func (fw *FakeFirewall) listenFTP() {
	var err error
	fw.ftpListener, err = net.Listen("tcp", fw.Config.ListenFTP)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting FTP server on %s\n", fw.Config.ListenFTP)
	for {
		conn, err := fw.ftpListener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			break
		}
		go fw.handleFTPConnection(conn)
	}
}

func (fw *FakeFirewall) handleFTPConnection(conn net.Conn) {
	defer conn.Close()
	
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	
	if !fw.checkRateLimit(remoteAddr.IP.String()) {
		log.Printf("Rate limit exceeded for FTP connection from %s\n", remoteAddr.IP)
		return
	}
	
	log.Printf("FTP connection from %s\n", remoteAddr.IP)
	
	fmt.Fprintf(conn, "220 Welcome to FTP server\r\n")
	
	scanner := bufio.NewScanner(conn)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	
	for scanner.Scan() {
		command := scanner.Text()
		log.Printf("FTP command from %s: %s\n", remoteAddr.IP, command)
		
		time.Sleep(time.Duration(rand.Intn(300)) * time.Millisecond)
		
		parts := strings.SplitN(command, " ", 2)
		cmd := parts[0]
		
		if response, ok := fw.FTPResponses[cmd]; ok {
			fmt.Fprintf(conn, response)
			log.Printf("FTP response to %s: %s", remoteAddr.IP, response)
		} else {
			fmt.Fprintf(conn, "500 Unknown command.\r\n")
			log.Printf("FTP unknown command response to %s: 500 Unknown command.\r\n", remoteAddr.IP)
		}
		
		if cmd == "QUIT" {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading FTP command: %v\n", err)
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
