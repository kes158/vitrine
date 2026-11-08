// sgwg-testpeer runs a throw-away WireGuard server for the macOS URLSession
// harness (tests/wireguard). It writes a client profile with freshly generated
// test keys, the fixture HTTPS certificate and a ready file to -out, then serves
// hit counters as JSON on 127.0.0.1 until it is terminated.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"sgwg/internal/testpeer"
)

func main() {
	out := flag.String("out", "", "output directory")
	listen := flag.String("listen", "127.0.0.1", "UDP listen host written into the client profile")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		os.Exit(2)
	}
	peer, err := testpeer.Start(testpeer.Options{ListenAddr: *listen})
	if err != nil {
		fmt.Fprintln(os.Stderr, "peer:", err)
		os.Exit(1)
	}
	defer peer.Close()
	stats, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "stats:", err)
		os.Exit(1)
	}
	go http.Serve(stats, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]int64{
			"dns": peer.DNSQueries.Load(), "http": peer.HTTPHits.Load(),
			"https": peer.HTTPSHits.Load(), "range": peer.RangeHits.Load(),
		})
	}))
	must := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	must(os.WriteFile(filepath.Join(*out, "client.conf"), []byte(peer.ClientConfig), 0o600))
	must(os.WriteFile(filepath.Join(*out, "fixture.der"), peer.CertDER, 0o644))
	ready, _ := json.Marshal(map[string]int{"udpPort": peer.Port, "statsPort": stats.Addr().(*net.TCPAddr).Port})
	must(os.WriteFile(filepath.Join(*out, "ready.json"), ready, 0o644))
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
}
