# portmux
Serve multiple protocols on one port by sniffing the first bytes of each connection — HTTP, TLS (SNI/ALPN), PROXY protocol, custom prefixes — and routing them to separate net.Listeners. Pure Go, stdlib only.
