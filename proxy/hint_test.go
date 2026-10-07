package proxy

import (
	"reflect"
	"testing"
)

func TestSchemaFromURL(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt", "socks5"},
		{"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "socks4"},
		{"https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/main/proxies/protocols/http/data.txt", "http"},
		{"https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/main/proxies/protocols/https/data.txt", "https"},
		{"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000", "socks4"},
		{"https://www.proxy-list.download/api/v1/get?type=https", "https"},
		{"https://api.openproxy.space/list/socks5", "socks5"},
		{"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt", ""},
		{"https://proxydb.net/?offset=10&sort_column_id=checked&sort_order_desc=true", ""},
		{"https://spys.one/en/", ""},
		{"https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/http.txt", "http"},
		{"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt", "socks5"},
	}
	for _, c := range cases {
		if got := schemaFromURL(c.url); got != c.want {
			t.Errorf("schemaFromURL(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

func TestPreferFirst(t *testing.T) {
	base := []string{"http", "socks5", "socks4", "https"}
	if got := preferFirst(base, "socks5"); !reflect.DeepEqual(got, []string{"socks5", "http", "socks4", "https"}) {
		t.Fatalf("preferFirst socks5 = %v", got)
	}
	if got := preferFirst(base, "https"); !reflect.DeepEqual(got, []string{"https", "http", "socks5", "socks4"}) {
		t.Fatalf("preferFirst https = %v", got)
	}
	// Already-first protocol must not corrupt or duplicate the order.
	if got := preferFirst(base, "http"); !reflect.DeepEqual(got, base) {
		t.Fatalf("preferFirst http = %v, want %v", got, base)
	}
}
