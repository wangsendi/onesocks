package service

import (
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing/common/control"
)

func newSubscriptionTransport(options Options) *http.Transport {
	transport := &http.Transport{
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if options.OutboundInterface != "" {
		transport.DialContext = newBoundSubscriptionDialer(options).DialContext
	}
	return transport
}

func newBoundSubscriptionDialer(options Options) *net.Dialer {
	dialer := &net.Dialer{
		Timeout:   options.FetchTimeout,
		KeepAlive: 30 * time.Second,
		Control:   control.BindToInterface(control.NewDefaultInterfaceFinder(), options.OutboundInterface, -1),
	}
	dialer.Resolver = &net.Resolver{
		PreferGo: true,
		// Resolver.Dial supplies a numeric DNS server address, so this also
		// binds DNS without recursively resolving the DNS server itself.
		Dial: dialer.DialContext,
	}
	return dialer
}
