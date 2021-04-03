# ZX2C4 DDNS Server

This is a simple Linux daemon for serving DNS queries for dynamic IP addresses.
It starts a TLS server on port 443, acquires a Let's Encrypt certificate for
it, and starts a DNS server on port 53. It then listens for authenticated
dynamic DNS updates over TLS and serves the updated IPs over DNS.

### Installation

Requirements: `make`, `go`, `systemd`.

```
# make
# make install
```

### Usage

First populate `/etc/ddns.conf` with a newly generated secret (created with
`ddns generate-secret`) and your ddns domain name:

```
DDNS_UPDATE_DOMAIN=ddns.example.org
DDNS_SECRET=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
```

Then enable and start the socket-activated daemon:

```
# systemctl enable ddns.socket
# systemctl install ddns.socket
```

Finally, generate domain update keys using `ddns generate-domain-key`:

```
# . /etc/ddns.conf; export DDNS_UPDATE_DOMAIN DDNS_SECRET
# ddns generate-domain-key somesubdomain.dyn.example.org
...
# ddns generate-domain-key !restrictivesubdomain.dyn.example.org
...
```

If the provided subdomain does _not_ start with a `!`, then that key can be
used for that subdomain and all subdomains of it. Caution: this allows for an
unbounded quantity of entries! If the provided subdomain _does_ start with a
`!`, then that key can only be used for that exact subdomain.

Updates can then be performed using any HTTPS utility:

```
# curl -H 'Domain-Key: 8N+TsT8GxFCAQ5Nn7yytOLFJX+PRe/ALXOx8A1J3dng=' https://ddns.example.org/update/demo.somesubdomain.dyn.example.org
```

### NS Entry

Direct DNS queries for various subdomains toward your DDNS server:

```
dyn.example.org. IN NS ddns.example.org.
```

### License

This project is released under the [GPLv2](COPYING).
