package psiphon

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	socks "github.com/Psiphon-Labs/goptlib"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
)

type SwitchConn struct {
	net.Conn
	*bufio.Reader
}

func NewSwitchConn(conn net.Conn) *SwitchConn {
	return &SwitchConn{
		Conn:   conn,
		Reader: bufio.NewReaderSize(conn, 2048),
	}
}

func (c *SwitchConn) Read(p []byte) (n int, err error) {
	return c.Reader.Read(p)
}

var LatestConn net.Conn

type SocksProxyMixer struct {
	listener net.Listener
}

func (mixer SocksProxyMixer) Accept() (net.Conn, error) {
	return LatestConn, nil
}

func (mixer *SocksProxyMixer) Close() error {
	return mixer.listener.Close()
}

func (mixer *SocksProxyMixer) Addr() net.Addr {
	return mixer.listener.Addr()
}

type HttpProxyMixer struct {
	listener net.Listener
	channel  chan net.Conn
}

func (mixer HttpProxyMixer) Accept() (net.Conn, error) {
	return <-mixer.channel, nil
}

func (mixer HttpProxyMixer) Close() error {
	return mixer.listener.Close()
}

func (mixer HttpProxyMixer) Addr() net.Addr {
	return mixer.listener.Addr()
}

type MixedProxy struct {
	config                 *Config
	tunneler               Tunneler
	listener               net.Listener
	socksMixer             SocksProxyMixer
	httpMixer              HttpProxyMixer
	socksListener          *socks.SocksListener
	httpProxy              HttpProxy
	serveWaitGroup         *sync.WaitGroup
	openConns              *common.Conns[net.Conn]
	stopListeningBroadcast chan struct{}
}

func NewMixedProxy(
	config *Config,
	tunneler Tunneler,
	listenIP string) (proxy *MixedProxy, err error) {

	listener, portInUse, err := makeLocalProxyListener(
		listenIP, config.LocalSocksProxyPort)
	if err != nil {
		if portInUse {
			NoticeSocksProxyPortInUse(config.LocalSocksProxyPort)
			NoticeHttpProxyPortInUse(config.LocalHttpProxyPort)
		}
		return nil, errors.Trace(err)
	}
	serveWaitGroup := new(sync.WaitGroup)

	socksMixer := SocksProxyMixer{listener: listener}
	httpMixer := HttpProxyMixer{listener: listener, channel: make(chan net.Conn)}

	tunneledDialer := func(_, addr string) (conn net.Conn, err error) {
		// downstreamConn is not set in this case, as there is not a fixed
		// association between a downstream client connection and a particular
		// tunnel.
		return tunneler.Dial(addr, nil)
	}
	directDialer := func(_, addr string) (conn net.Conn, err error) {
		return tunneler.DirectDial(addr)
	}

	p := config.GetParameters().Get()
	responseHeaderTimeout := p.Duration(parameters.HTTPProxyOriginServerTimeout)
	maxIdleConnsPerHost := p.Int(parameters.HTTPProxyMaxIdleConnectionsPerHost)

	// TODO: could HTTP proxy share a tunneled transport with URL proxy?
	// For now, keeping them distinct just to be conservative.
	httpProxyTunneledRelay := &http.Transport{
		Dial:                  tunneledDialer,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}

	// Note: URL proxy relays use http.Client for upstream requests, so
	// redirects will be followed. HTTP proxy should not follow redirects
	// and simply uses http.Transport directly.

	urlProxyTunneledRelay := &http.Transport{
		Dial:                  tunneledDialer,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	urlProxyTunneledClient := &http.Client{
		Transport: urlProxyTunneledRelay,
		Jar:       nil, // TODO: cookie support for URL proxy?

		// Leaving original value in the note below:
		// Note: don't use this timeout -- it interrupts downloads of large response bodies
		//Timeout:   HTTP_PROXY_ORIGIN_SERVER_TIMEOUT,
	}

	urlProxyDirectRelay := &http.Transport{
		Dial:                  directDialer,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	urlProxyDirectClient := &http.Client{
		Transport: urlProxyDirectRelay,
		Jar:       nil,
	}

	proxyIP, proxyPortString, _ := net.SplitHostPort(listener.Addr().String())
	proxyPort, _ := strconv.Atoi(proxyPortString)

	proxy = &MixedProxy{
		config:        config,
		tunneler:      tunneler,
		listener:      listener,
		socksMixer:    socksMixer,
		httpMixer:     httpMixer,
		socksListener: socks.NewSocksListener(&socksMixer),
		httpProxy: HttpProxy{
			config:                 config,
			tunneler:               tunneler,
			listener:               httpMixer,
			serveWaitGroup:         serveWaitGroup,
			httpProxyTunneledRelay: httpProxyTunneledRelay,
			urlProxyTunneledRelay:  urlProxyTunneledRelay,
			urlProxyTunneledClient: urlProxyTunneledClient,
			urlProxyDirectRelay:    urlProxyDirectRelay,
			urlProxyDirectClient:   urlProxyDirectClient,
			responseHeaderTimeout:  responseHeaderTimeout,
			openConns:              common.NewConns[net.Conn](),
			stopListeningBroadcast: make(chan struct{}),
			listenIP:               proxyIP,
			listenPort:             proxyPort,
		},
		serveWaitGroup:         serveWaitGroup,
		openConns:              common.NewConns[net.Conn](),
		stopListeningBroadcast: make(chan struct{}),
	}
	proxy.serveWaitGroup.Add(1)
	go proxy.serve()
	NoticeListeningSocksProxyPort(proxy.listener.Addr().(*net.TCPAddr).Port)
	NoticeListeningHttpProxyPort(proxy.httpProxy.listenPort)
	return proxy, nil
}

// Close terminates the listener and waits for the accept loop
// goroutine to complete.
func (proxy *MixedProxy) Close() {
	close(proxy.stopListeningBroadcast)
	proxy.listener.Close()
	proxy.serveWaitGroup.Wait()
	proxy.openConns.CloseAll()
}

func (proxy *MixedProxy) socksConnectionHandler(localConn *socks.SocksConn) (err error) {
	defer localConn.Close()
	defer proxy.openConns.Remove(localConn)

	proxy.openConns.Add(localConn)

	// Using downstreamConn so localConn.Close() will be called when remoteConn.Close() is called.
	// This ensures that the downstream client (e.g., web browser) doesn't keep waiting on the
	// open connection for data which will never arrive.
	remoteConn, err := proxy.tunneler.Dial(localConn.Req.Target, localConn)

	if err != nil {
		reason := byte(socks.SocksRepGeneralFailure)

		// "ssh: rejected" is the prefix of ssh.OpenChannelError
		// TODO: retain error type and check for ssh.OpenChannelError
		if strings.Contains(err.Error(), "ssh: rejected") {
			reason = byte(socks.SocksRepConnectionRefused)
		}

		_ = localConn.RejectReason(reason)
		return errors.Trace(err)
	}

	defer remoteConn.Close()

	err = localConn.Grant(&net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
	if err != nil {
		return errors.Trace(err)
	}

	LocalProxyRelay(proxy.config, _SOCKS_PROXY_TYPE, localConn, remoteConn)

	return nil
}

func (proxy *MixedProxy) serve() {
	defer proxy.listener.Close()
	defer proxy.serveWaitGroup.Done()

	go func() {
		httpServer := &http.Server{
			Handler:   &proxy.httpProxy,
			ConnState: proxy.httpProxy.httpConnStateCallback,
		}
		err := httpServer.Serve(&proxy.httpMixer)
		select {
		case <-proxy.stopListeningBroadcast:
		default:
			if err != nil {
				proxy.tunneler.SignalComponentFailure()
				NoticeLocalProxyError(_HTTP_PROXY_TYPE, errors.Trace(err))
			}
		}
		NoticeInfo("HTTP proxy stopped")
	}()

loop:
	for {
		conn, err := proxy.listener.Accept()
		select {
		case <-proxy.stopListeningBroadcast:
			break loop
		default:
		}
		if err != nil {
			NoticeWarning("mixed proxy accept error: %s", err)
			if e, ok := err.(net.Error); ok && e.Temporary() {
				// Temporary error, keep running
				continue
			}
			// Fatal error, stop the proxy
			proxy.tunneler.SignalComponentFailure()
			break loop
		}

		switchConn := NewSwitchConn(conn)

		buf, err := switchConn.Peek(1)
		if err != nil {
			NoticeWarning("mixed proxy peek error: %s", err)
			continue
		}

		switch buf[0] {
		case 4, 5:
			LatestConn = switchConn
			socksConnection, err := proxy.socksListener.AcceptSocks()
			if err != nil {
				NoticeWarning("SOCKS proxy accept error: %s", err)
				if e, ok := err.(net.Error); ok && e.Temporary() {
					// Temporary error, keep running
					continue
				}
				// Fatal error, stop the proxy
				proxy.tunneler.SignalComponentFailure()
				break loop
			}

			go func() {
				err := proxy.socksConnectionHandler(socksConnection)
				if err != nil {
					NoticeLocalProxyError(_SOCKS_PROXY_TYPE, errors.Trace(err))
				}
			}()

			break
		default:
			proxy.httpMixer.channel <- switchConn
		}
	}
	NoticeInfo("mixed proxy stopped")
}
