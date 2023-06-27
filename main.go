package main

import (
	"goProxy/core/config"
	"goProxy/core/pnc"
	"goProxy/core/server"
	"io"
	"log"
	"net"
	"os"
)

var ipWhitelist = []string{
	"176.97.210.166",
	"87.237.52.211",
}

func main() {

	// Check if the local IP is whitelisted
	localIP, err := getLocalIP()
	if err != nil {
		log.Fatalf("Failed to get local IP: %v", err)
	}

	if !isWhitelisted(localIP) {
		log.Fatalf("Local IP %s is not whitelisted. Exiting.", localIP)
	}

	logFile, err := os.OpenFile("crash.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	pnc.InitHndl()

	defer pnc.PanicHndl()

	//Disable Error Logging
	log.SetOutput(io.Discard)

	config.Load()

	go server.Serve()
	go server.Monitor()

	//Keep server running
	select {}
}

func isWhitelisted(ip string) bool {
	for _, whitelistedIP := range ipWhitelist {
		if ip == whitelistedIP {
			return true
		}
	}
	return false
}

func getLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.String(), nil
}