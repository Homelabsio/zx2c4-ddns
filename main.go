/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/blake2s"
	"inet.af/netaddr"
)

var (
	domains               = make(map[string]netaddr.IP, 32)
	domainsLock           sync.RWMutex
	saving                sync.Mutex
	serializedDomainsFile string
	secret                []byte
)

func normalizeDomain(domain string) string {
	domain = strings.ToLower(domain)
	if _, ok := dns.IsDomainName(domain); !ok {
		return ""
	}
	return strings.Join(dns.SplitDomainName(domain), ".") + "."
}

func load() {
	fileContents, err := os.ReadFile(serializedDomainsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: unable to read saved domains: %v\n", err)
		return
	}
	for _, line := range bytes.Split(fileContents, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		parts := bytes.SplitN(line, []byte{'\t'}, 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Warning: unable to parse saved line: %q\n", line)
			continue
		}
		ip, err := netaddr.ParseIP(string(parts[0]))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: unable to parse saved ip: %q\n", parts[0])
			continue
		}
		domain := normalizeDomain(string(parts[1]))
		if domain == "" {
			fmt.Fprintf(os.Stderr, "Warning: unable to parse saved domain: %q\n", string(parts[1]))
			continue
		}
		domainsLock.Lock()
		domains[domain] = ip
		domainsLock.Unlock()
	}
}

func save() {
	saving.Lock()
	defer saving.Unlock()
	f, err := os.CreateTemp(filepath.Dir(serializedDomainsFile), filepath.Base(serializedDomainsFile)+"-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: unable to create temp file: %v\n", err)
		return
	}
	tmpName := f.Name()
	domainsLock.RLock()
	for domain, ip := range domains {
		_, err2 := fmt.Fprintf(f, "%v\t%s\n", ip, domain)
		if err2 != nil {
			err = err2
		}
	}
	domainsLock.RUnlock()
	err2 := f.Close()
	if err == nil {
		err = err2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: unable to write to temp file: %v\n", err)
		_ = os.Remove(tmpName)
		return
	}
	err = os.Rename(tmpName, serializedDomainsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: unable to rename temp file to destination file: %v\n", err)
		_ = os.Remove(tmpName)
	}
}

func handleUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Server", "ZX2C4 DDNS/1.0")
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ip, err := netaddr.ParseIP(host)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	wantUpdate, domain := path.Split(r.URL.Path)
	if wantUpdate != "/update/" {
		http.NotFound(w, r)
		return
	}
	domain = normalizeDomain(domain)
	if domain == "" || strings.IndexByte(domain, '!') != -1 {
		http.NotFound(w, r)
		return
	}
	domainKey, err := base64.StdEncoding.DecodeString(r.Header.Get("Domain-Key"))
	if err != nil || len(domainKey) != 32 {
		http.NotFound(w, r)
		return
	}
	hasher, err := blake2s.New256(secret)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	hasher.Write([]byte("!" + domain))
	authed := hmac.Equal(hasher.Sum(nil), domainKey)
	split := dns.SplitDomainName(domain)
	for i := len(split); i >= 0 && !authed; i-- {
		hasher.Reset()
		hasher.Write([]byte(strings.Join(split[i:], ".") + "."))
		authed = hmac.Equal(hasher.Sum(nil), domainKey)
	}
	if !authed {
		http.NotFound(w, r)
		return
	}
	domainsLock.Lock()
	domains[domain] = ip
	domainsLock.Unlock()
	go save()
}

func handleDns(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	for _, q := range r.Question {
		domain := normalizeDomain(q.Name)
		if domain == "" {
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			return
		}
		domainsLock.RLock()
		ip, ok := domains[domain]
		domainsLock.RUnlock()
		if !ok {
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			return
		}
		if q.Qtype == dns.TypeA && ip.Is4() {
			v4 := ip.As4()
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   v4[:],
			})
		} else if q.Qtype == dns.TypeAAAA && ip.Is6() {
			v6 := ip.As16()
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30},
				AAAA: v6[:],
			})
		}
	}
	w.WriteMsg(m)
}

func systemdSockets() []*os.File {
	var files []*os.File
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		return files
	}
	fds, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || fds == 0 {
		return files
	}
	const SD_LISTEN_FDS_START = 3
	for fd := SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START+fds; fd++ {
		syscall.CloseOnExec(fd)
		files = append(files, os.NewFile(uintptr(fd), ""))
	}
	return files
}

func startDnsServers(udp, tcp *os.File) {
	dnsUdpListener, err := net.FilePacketConn(udp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: unable to listen on %v: %v\n", udp, err)
		os.Exit(1)
	}
	go func() {
		server := dns.Server{PacketConn: dnsUdpListener}
		if err := server.ActivateAndServe(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: unable to serve DNS on %v: %v\n", dnsUdpListener, err)
			os.Exit(1)
		}
	}()
	dnsTcpListener, err := net.FileListener(tcp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: unable to listen on %v: %v\n", tcp, err)
		os.Exit(1)
	}
	go func() {
		server := dns.Server{Listener: dnsTcpListener}
		if err := server.ActivateAndServe(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: unable to serve DNS on %v: %v\n", dnsTcpListener, err)
			os.Exit(1)
		}
	}()
}

type tlsListener struct {
	conf *tls.Config
	listener  net.Listener
}

func (ln *tlsListener) Accept() (net.Conn, error) {
	conn, err := ln.listener.Accept()
	if err != nil {
		return nil, err
	}
	tcpConn := conn.(*net.TCPConn)
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(3 * time.Minute)
	return tls.Server(tcpConn, ln.conf), nil
}

func (ln *tlsListener) Addr() net.Addr {
	return ln.listener.Addr()
}

func (ln *tlsListener) Close() error {
	return ln.Close()
}

func newAutocertListener(tcp *os.File, cacheDir, domain string) net.Listener {
	cacheDir = filepath.Join(cacheDir, "tls-certs")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error: unable to create cert cache directory: %v\n", err)
		os.Exit(1)
	}
	listener, err := net.FileListener(tcp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: unable to create file listener: %v\n", err)
	}
	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      autocert.DirCache(cacheDir),
	}
	return &tlsListener{
		conf:     m.TLSConfig(),
		listener: listener,
	}
}

func usage() {
	fmt.Fprintf(os.Stderr,
		`Usage: %s generate-secret
       %s generate-domain-key [!]DOMAIN
       %s serve

The generate-secret subcommand simply prints out a new random secret for use
in the DDNS_SECRET environment variable.

The generate-domain-key subcommand generates a key to be used with the
Domain-Secret http header when making update requests. If DOMAIN begins
with a '!', the key may only be used for that exact domain. Otherwise the
key is usable for that domain and all subdomains of it; beware, there is no
limit on the number of entries such an unrestricted key can add. The
DDNS_SECRET environment variable must be set and of valid form.

The serve subcommand starts a DNS server and a HTTPS update server on the
domain specified by the DDNS_UPDATE_DOMAIN environment variable. Open file
descriptors must be passed in with systemd socket-activation semantics, in
order udp:53, tcp:53, tcp:443. The DDNS_SECRET environment variable must be
set and of valid form. The /update/{DOMAIN} http endpoint requires the
Domain-Secret http header to be set. Domains will be read from and stored
to $STATE_DIRECTORY/domains.txt, and TLS certificates will be stored in
$CACHE_DIRECTORY/ddns-certs.
`, os.Args[0], os.Args[0], os.Args[0])
	os.Exit(1)
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "generate-secret" {
		var bytes [32]byte
		_, err := rand.Read(bytes[:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: unable to read random bytes: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(bytes[:]))
		return
	}

	var err error
	secret, err = base64.StdEncoding.DecodeString(os.Getenv("DDNS_SECRET"))
	if err != nil || len(secret) != 32 {
		fmt.Fprintln(os.Stderr, "Error: DDNS_SECRET is not valid\n")
		usage()
	}

	if len(os.Args) == 3 && os.Args[1] == "generate-domain-key" {
		domain := os.Args[2]
		var split []string
		var exclusive string
		if len(domain) > 0 && domain[0] == '!' {
			exclusive = "!"
			domain = domain[1:]
		}
		if domain != "" {
			domain = normalizeDomain(domain)
			if domain == "" {
				fmt.Fprintln(os.Stderr, "Error: domain is not valid")
				os.Exit(1)
			}
			split = dns.SplitDomainName(domain)
		}
		hasher, err := blake2s.New256(secret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: unable to create hasher: %v\n", err)
			os.Exit(1)
		}
		hasher.Write([]byte(exclusive + strings.Join(split, ".") + "."))
		key := base64.StdEncoding.EncodeToString(hasher.Sum(nil))
		fmt.Println(key)
		updateDomain := os.Getenv("DDNS_UPDATE_DOMAIN")
		if updateDomain == "" {
			updateDomain = "ddns.example.org"
		}
		fmt.Printf("Command: curl -H 'Domain-Key: %s' https://%s/update/%s\n", key, updateDomain, domain[:len(domain)-1])
		return
	}

	if len(os.Args) != 2 || os.Args[1] != "serve" {
		usage()
	}

	serializedDomainsFile = os.Getenv("STATE_DIRECTORY")
	if serializedDomainsFile == "" {
		fmt.Fprintf(os.Stderr, "Error: STATE_DIRECTORY is unset\n\n")
		usage()
	}
	serializedDomainsFile = filepath.Join(serializedDomainsFile, "domains.txt")

	cacheDir := os.Getenv("CACHE_DIRECTORY")
	if cacheDir == "" {
		fmt.Fprintf(os.Stderr, "Error: CACHE_DIRECTORY is unset\n\n")
		usage()
	}

	updateDomain := os.Getenv("DDNS_UPDATE_DOMAIN")
	if updateDomain == "" {
		fmt.Fprintf(os.Stderr, "Error: DDNS_UPDATE_DOMAIN is unset\n\n")
		usage()
	}

	load()

	files := systemdSockets()
	if len(files) != 3 {
		fmt.Fprintln(os.Stderr, "Error: expected to receive 3 activated sockets")
		os.Exit(1)
	}

	dns.HandleFunc(".", handleDns)
	startDnsServers(files[0], files[1])

	http.HandleFunc("/update/", handleUpdate)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://git.zx2c4.com/zx2c4-ddns/about/", 302)
	})
	err = http.Serve(newAutocertListener(files[2], cacheDir, updateDomain), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: unable to serve https: %v\n", err)
		os.Exit(1)
	}
}
