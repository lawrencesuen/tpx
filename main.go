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
	"sync"
	"time"
)

type TPXServer struct {
	debug       TPXDebugLevel
	resolver    *net.Resolver
	ipAllowed   map[string]bool
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
		debug:       debug,
		ipAllowed:   map[string]bool{},
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
	if tpx.apiURL != "" || tpx.accessToken != "" {
		// there is an api url or access token, so we need to check if the connection is allowed
		// get the ip address of the client
		ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			if tpx.debug >= TPXDebugLevelInfo {
				log.Println("error getting remote address: ", err.Error())
			}
			return
		}
		// check if the ip is allowed
		if !tpx.ipAllowed[ip] {
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

	// connect to actual server
	if tpx.debug >= TPXDebugLevelInfo {
		log.Println("connecting to remote server: ", *info.Info.ServerName)
	}

	addrs, err := tpx.resolver.LookupHost(context.Background(), *info.Info.ServerName)
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

type GetAllowedIPJSON struct {
	AllowedIPs []string `json:"allowed_ips"`
}

func (tpx *TPXServer) updateAllowedIPs() error {
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
	var allowedIPs GetAllowedIPJSON
	err = json.Unmarshal(body, &allowedIPs)
	if err != nil {
		return err
	}

	// create the map
	ipAllowed := map[string]bool{}
	for _, ip := range allowedIPs.AllowedIPs {
		ipAllowed[ip] = true
	}

	tpx.ipAllowed = ipAllowed
	return nil
}

func (tpx *TPXServer) updateHandler(w http.ResponseWriter, r *http.Request) {
	// check authorization
	if tpx.accessToken != "" {
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
	}
	w.WriteHeader(http.StatusOK)
	// this will trigger system to make API call to get new list of IPs
	if err := tpx.updateAllowedIPs(); err != nil {
		log.Println("error getting allowed ips: ", err.Error())
		return
	}
}

func (tpx *TPXServer) startAPIServer() {
	// create a new mux
	mux := http.NewServeMux()
	// add the handler
	mux.HandleFunc("/update", tpx.updateHandler)
	// start the server
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func (tpx *TPXServer) Start() {

	if tpx.apiURL != "" {
		// if api url is set, then we need to call the API to get the list of allowed ips
		// get the list of allowed ips
		err := tpx.updateAllowedIPs()
		if err != nil {
			log.Fatal("error getting allowed ips: ", err.Error())
		}
	}

	if tpx.accessToken != "" {
		// if access token is set, then we need to start web server to handle API calls for updates to allowed ips
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
