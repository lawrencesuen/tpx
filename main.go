// Copyright 2023 Lawrence Suen
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the “Software”), to deal in
// the Software without restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
// Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

package main

import (
	"appsverse/tpx/tlsparser"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ConfigJSON struct {
	IPControl          bool     `json:"ipControl"`
	DefaultAllowIP     bool     `json:"defaultAllowIP"`
	AllowedIPs         []string `json:"allowedIPs"`
	BlockedIPs         []string `json:"blockedIPs"`
	DomainControl      bool     `json:"domainControl"`
	DefaultAllowDomain bool     `json:"defaultAllowDomain"`
	AllowedDomains     []string `json:"allowedDomains"`
	BlockedDomains     []string `json:"blockedDomains"`
}

type AccessControlConfig struct {
	ipControl           bool
	ipAccessControl     map[string]bool
	defaultAllowIP      bool
	domainControl       bool
	domainAccessControl map[string]bool
	defaultAllowDomain  bool
}

type TPXServer struct {
	debug       TPXDebugLevel
	resolver    *net.Resolver
	config      *AccessControlConfig
	apiURL      string
	accessToken string
}

type TPXDebugLevel int

const (
	TPXDebugLevelNone TPXDebugLevel = 0
	TPXDebugLevelInfo TPXDebugLevel = 1
	TPXDebugLevelFull TPXDebugLevel = 2
)

func NewTPXServer(dnsIP string, debug TPXDebugLevel, apiURL string, accessToken string) *TPXServer {
	tpx := &TPXServer{
		debug: debug,
		config: &AccessControlConfig{
			ipControl:           false,
			ipAccessControl:     map[string]bool{},
			defaultAllowIP:      false,
			domainControl:       false,
			domainAccessControl: map[string]bool{},
			defaultAllowDomain:  false,
		},
		apiURL:      apiURL,
		accessToken: accessToken,
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}

	if dnsIP != "" {
		dnsServerString := fmt.Sprintf("%s:%d", dnsIP, 53)
		tpx.resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(5000),
			}
			return d.DialContext(ctx, network, dnsServerString)
		}
	}

	return tpx
}

func (tpx *TPXServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// check if connection is allowed
	// there is an api url or access token, so we need to check if the connection is allowed
	// get the ip address of the client
	ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		if tpx.debug >= TPXDebugLevelInfo {
			log.Println("error getting remote address: ", err.Error())
		}
		return
	}

	if tpx.config.ipControl {
		// check if the ip is allowed
		accessControlResult, ok := tpx.config.ipAccessControl[ip]

		if !ok {
			accessControlResult = tpx.config.defaultAllowIP
		}

		if !accessControlResult {
			if tpx.debug >= TPXDebugLevelInfo {
				log.Println("ip not allowed: ", ip)
			}
			return
		}
	}

	// create reader and writer
	tlsParserConnection, err := tlsparser.NewConn(conn)
	if err != nil {
		if tpx.debug >= TPXDebugLevelInfo {
			log.Println("error creating tls parser connection: ", err.Error())
		}
		return
	}
	info := tlsparser.UnmarshalClientHello(tlsParserConnection.ClientHello)

	targetDomainName := strings.ToLower(*info.Info.ServerName)

	if len(targetDomainName) < 4 || len(targetDomainName) > 255 {
		if tpx.debug >= TPXDebugLevelInfo {
			log.Println("domain too long or too short: ", targetDomainName)
		}
		return
	}

	if tpx.config.domainControl {
		// check if the domain is allowed

		// split by dot
		domainParts := strings.Split(targetDomainName, ".")

		if len(domainParts) < 2 || len(domainParts) > 10 {
			// invalid domain
			if tpx.debug >= TPXDebugLevelInfo {
				log.Println("invalid domain: ", targetDomainName)
			}
			return
		}

		for i := 0; i < len(domainParts)-1; i++ {
			subDomainName := strings.Join(domainParts[i:], ".")

			domainAllowed, ok := tpx.config.domainAccessControl[subDomainName]

			if !ok {
				// no match
				// is this the last one?
				if i == len(domainParts)-2 {
					// yes, use the default
					domainAllowed = tpx.config.defaultAllowDomain
				} else {
					// no, continue
					continue
				}
			}

			if !domainAllowed {
				if tpx.debug >= TPXDebugLevelInfo {
					log.Println("domain not allowed: ", targetDomainName)
				}
				return
			}
		}
	}

	// connect to actual server
	if tpx.debug >= TPXDebugLevelInfo {
		log.Println("looking up remote server: ", targetDomainName)
	}

	addrs, err := tpx.resolver.LookupHost(context.Background(), targetDomainName)
	if err != nil {
		if tpx.debug >= TPXDebugLevelInfo {
			log.Println("error resolving remote server: ", err.Error())
		}
		return
	}

	if len(addrs) == 0 {
		if tpx.debug >= TPXDebugLevelInfo {
			log.Println("no addresses found for remote server: ", *info.Info.ServerName)
		}
		return
	}

	// pick a random address
	addr := addrs[rand.Intn(len(addrs))]

	if tpx.debug >= TPXDebugLevelInfo {
		log.Println("connecting to remote server: ", addr, " on port 443")
	}

	remoteConnection, err := net.Dial("tcp", fmt.Sprintf("%s:%d", addr, 443))
	if err != nil {
		if tpx.debug >= TPXDebugLevelInfo {
			log.Println("error connecting to remote server: ", err.Error())
		}
		return
	}
	if tpx.debug >= TPXDebugLevelInfo {
		log.Println("connected to remote server: ", addr, " on port 443")
	}

	defer remoteConnection.Close()

	// create reader and writer
	var waiter sync.WaitGroup
	waiter.Add(2)
	go func() {
		if _, err := io.Copy(tlsParserConnection, remoteConnection); err != nil {
			if tpx.debug >= TPXDebugLevelInfo {
				log.Println("error copying from remote server: ", err.Error())
			}
		}
		if tpx.debug >= TPXDebugLevelInfo {
			log.Println("closing remote connection")
		}
		tlsParserConnection.Close()
		remoteConnection.Close()
		waiter.Done()
	}()
	go func() {
		if _, err := io.Copy(remoteConnection, tlsParserConnection); err != nil {
			log.Println("error copying to remote server: ", err.Error())
		}
		if tpx.debug >= TPXDebugLevelInfo {
			log.Println("closing remote connection")
		}
		tlsParserConnection.Close()
		remoteConnection.Close()
		waiter.Done()
	}()

	// wait for streaming to end
	waiter.Wait()

	if tpx.debug >= TPXDebugLevelInfo {
		log.Println("connection closed")
	}
}

func (tpx *TPXServer) getConfig() error {
	// create a new request
	req, err := http.NewRequest("GET", tpx.apiURL, nil)
	if err != nil {
		return err
	}
	// add the access token to the header
	if tpx.accessToken != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tpx.accessToken))
	}
	// create a new client
	client := &http.Client{}
	// make the request
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// read the body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// unmarshal the body
	var configJSON ConfigJSON
	err = json.Unmarshal(body, &configJSON)
	if err != nil {
		return err
	}

	if err := tpx.processConfig(&configJSON); err != nil {
		return err
	}

	return nil
}

func (tpx *TPXServer) updateHandler(w http.ResponseWriter, r *http.Request) {
	// check authorization
	// get the authorization header
	authHeader := r.Header.Get("Authorization")
	// check if the header is empty
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// check if the header is valid
	if authHeader != fmt.Sprintf("Bearer %s", tpx.accessToken) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
	// this will trigger system to make API call to get new list of IPs
	if err := tpx.getConfig(); err != nil {
		log.Println("error getting allowed ips: ", err.Error())
		return
	}
}

func (tpx *TPXServer) startAPIServer() {
	// create a new mux
	mux := http.NewServeMux()
	// add the handler
	mux.HandleFunc("/triggerUpdate", tpx.updateHandler)
	// start the server
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func (tpx *TPXServer) processConfig(configJSON *ConfigJSON) error {
	// create the map
	ipAccessControl := map[string]bool{}
	for _, ip := range configJSON.AllowedIPs {
		ipAccessControl[ip] = true
	}

	for _, ip := range configJSON.BlockedIPs {
		ipAccessControl[ip] = false
	}

	domainAccessControl := map[string]bool{}
	for _, domainName := range configJSON.AllowedDomains {
		domainAccessControl[domainName] = true
	}

	for _, domainName := range configJSON.BlockedDomains {
		domainAccessControl[domainName] = false
	}

	config := &AccessControlConfig{
		ipControl:           configJSON.IPControl,
		ipAccessControl:     ipAccessControl,
		defaultAllowIP:      configJSON.DefaultAllowIP,
		domainControl:       configJSON.DomainControl,
		domainAccessControl: domainAccessControl,
		defaultAllowDomain:  configJSON.DefaultAllowDomain,
	}

	// we want to do this atomically
	tpx.config = config

	return nil
}

func (tpx *TPXServer) Start() {

	// read local config file

	configData, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatal("error reading config file: ", err.Error())
	}
	// parse config
	var config ConfigJSON
	err = json.Unmarshal(configData, &config)
	if err != nil {
		log.Fatal("error parsing config file: ", err.Error())
	}

	if err := tpx.processConfig(&config); err != nil {
		log.Fatal("error processing config: ", err.Error())
	}

	if tpx.apiURL != "" || tpx.accessToken != "" {
		if tpx.apiURL == "" || tpx.accessToken == "" {
			log.Fatal("api url and access token must both be set or not set at all")
		}
		// if api url is set, then we need to call the API to get the latest config
		err := tpx.getConfig()
		if err != nil {
			log.Fatal("error getting allowed ips: ", err.Error())
		}
		// we need to start web server to handle API calls for updates to allowed ips
		go tpx.startAPIServer()
	}

	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		// handle error
		log.Fatal("error listening on port 443: ", err.Error())
	}
	defer ln.Close()
	log.Println("TPX started, listening on port 443")
	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
			if tpx.debug >= TPXDebugLevelInfo {
				log.Println("error accepting connection: ", err.Error())
			}
			continue
		}
		go tpx.handleConnection(conn)
	}
}

func main() {
	dnsIP := os.Getenv("TPX_DNS_IP")
	debugString := os.Getenv("TPX_DEBUG")
	apiURL := os.Getenv("TPX_API_URL")
	accessToken := os.Getenv("TPX_ACCESS_TOKEN")
	var debug int64 = 0
	if debugString != "" {
		var err error
		debug, err = strconv.ParseInt(debugString, 10, 32)
		if err != nil {
			log.Fatal("error parsing debug level: ", err.Error())
		}
		if debug < int64(TPXDebugLevelNone) || debug > int64(TPXDebugLevelFull) {
			log.Fatal("invalid debug level: ", debug)
		}
	}
	tpx := NewTPXServer(dnsIP, TPXDebugLevel(debug), apiURL, accessToken)
	tpx.Start()
}
