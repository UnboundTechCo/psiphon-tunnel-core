package pt

import (
	"bufio"
	"bytes"
	"testing"
)

func TestSocks5NegotiateAuthPrefersUsernamePasswordWhenRequested(t *testing.T) {
	method, response := negotiateSocks5AuthForTest(t, true)

	if method != socksAuthUsernamePassword {
		t.Fatalf("method = %#x, want username/password", method)
	}
	if !bytes.Equal(response, []byte{socks5Version, socksAuthUsernamePassword}) {
		t.Fatalf("response = %#v, want username/password selection", response)
	}
}

func TestSocks5NegotiateAuthKeepsPsiphonNoAuthDefault(t *testing.T) {
	method, response := negotiateSocks5AuthForTest(t, false)

	if method != socksAuthNoneRequired {
		t.Fatalf("method = %#x, want no-auth", method)
	}
	if !bytes.Equal(response, []byte{socks5Version, socksAuthNoneRequired}) {
		t.Fatalf("response = %#v, want no-auth selection", response)
	}
}

func TestSocks5NegotiateAuthRejectsNoAuthWhenUsernamePasswordRequired(t *testing.T) {
	input := bytes.NewBuffer([]byte{socks5Version, 1, socksAuthNoneRequired})
	var output bytes.Buffer
	rw := bufio.NewReadWriter(bufio.NewReader(input), bufio.NewWriter(&output))

	method, err := socks5NegotiateAuth(rw, true)
	if err != nil {
		t.Fatalf("socks5NegotiateAuth() error = %v", err)
	}
	if method != socksAuthNoAcceptableMethods {
		t.Fatalf("method = %#x, want no acceptable methods", method)
	}
	if !bytes.Equal(output.Bytes(), []byte{socks5Version, socksAuthNoAcceptableMethods}) {
		t.Fatalf("response = %#v, want no acceptable methods selection", output.Bytes())
	}
}

func TestSocks5AuthRFC1929RejectsInvalidCredentials(t *testing.T) {
	input := bytes.NewBuffer([]byte{
		socksAuthRFC1929Ver,
		4, 'u', 's', 'e', 'r',
		5, 'w', 'r', 'o', 'n', 'g',
	})
	var output bytes.Buffer
	rw := bufio.NewReadWriter(bufio.NewReader(input), bufio.NewWriter(&output))
	req := new(SocksRequest)

	err := socks5AuthRFC1929(rw, func(username, password string) bool {
		return username == "user" && password == "pass"
	}, req)
	if err == nil {
		t.Fatal("socks5AuthRFC1929() error = nil, want auth failure")
	}
	if !bytes.Equal(output.Bytes(), []byte{socksAuthRFC1929Ver, socksAuthRFC1929Fail}) {
		t.Fatalf("response = %#v, want RFC1929 auth failure", output.Bytes())
	}
}

func negotiateSocks5AuthForTest(t *testing.T, preferUsernamePassword bool) (byte, []byte) {
	t.Helper()
	input := bytes.NewBuffer([]byte{socks5Version, 2, socksAuthNoneRequired, socksAuthUsernamePassword})
	var output bytes.Buffer
	rw := bufio.NewReadWriter(bufio.NewReader(input), bufio.NewWriter(&output))

	method, err := socks5NegotiateAuth(rw, preferUsernamePassword)
	if err != nil {
		t.Fatalf("socks5NegotiateAuth() error = %v", err)
	}
	return method, output.Bytes()
}
