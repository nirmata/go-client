package client

import (
	"sync/atomic"

	"k8s.io/klog/v2"
)

// noCertPath identifies a constructor path that can build an internal https
// client without a client certificate. Each path warns at most once per process.
type noCertPath int

const (
	noCertPathNewClient noCertPath = iota
	noCertPathClientOptions
	noCertPathServiceClient
	numNoCertPaths
)

var noCertWarned [numNoCertPaths]atomic.Bool

// warnInternalNoClientCert logs a WARN, once per process per constructor path,
// when an internal https base URL is paired with a client the caller did not
// supply. Such a client presents no client certificate, so peers that enforce
// SPIRE mTLS fail the handshake with "certificate required". It only logs;
// behaviour is unchanged.
func warnInternalNoClientCert(path noCertPath, constructor, address, fix string) {
	if address != "https://" || !noCertWarned[path].CompareAndSwap(false, true) {
		return
	}
	klog.Warningf("go-client: %s built an internal https client (base URL %q) that presents no client certificate; "+
		"peers that enforce SPIRE mTLS will reject it with \"certificate required\". "+
		"Pass the SPIRE *http.Client via %s.", constructor, address, fix)
}
