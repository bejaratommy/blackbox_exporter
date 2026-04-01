// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sort"

	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"

	"github.com/prometheus/blackbox_exporter/config"
)

// queryResponseLabelNames collects the union of all label names across every
// query_response entry that defines labels, returning them in sorted order.
// Registering probe_expect_info once with this combined set avoids a panic
// when two entries define labels with different names (see GitHub #1526).
func queryResponseLabelNames(qrs []config.QueryResponse) []string {
	seen := make(map[string]struct{})
	for _, qr := range qrs {
		for _, l := range qr.Labels {
			seen[l.Name] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// probeExpectInfo records the captured label values for a single query_response
// match into the pre-registered metric vec.  Labels not present in this
// particular entry are emitted as empty strings so that WithLabelValues always
// receives exactly len(allNames) values.
func probeExpectInfo(metric *prometheus.GaugeVec, allNames []string, qr *config.QueryResponse, data []byte, match []int) {
	// Build a lookup of name → expanded value for this entry.
	entryValues := make(map[string]string, len(qr.Labels))
	for _, s := range qr.Labels {
		entryValues[s.Name] = string(qr.Expect.Expand(nil, []byte(s.Value), data, match))
	}

	// Emit in the canonical order (allNames) so WithLabelValues is correct.
	values := make([]string, len(allNames))
	for i, name := range allNames {
		values[i] = entryValues[name] // "" when not present in this entry
	}
	metric.WithLabelValues(values...).Set(1)
}

func probeQueryResponses(ctx context.Context, target string, conn net.Conn, module config.Module, proberName string, registry *prometheus.Registry, logger *slog.Logger) bool {
	probeSSLEarliestCertExpiry := prometheus.NewGauge(sslEarliestCertExpiryGaugeOpts)
	probeSSLLastChainExpiryTimestampSeconds := prometheus.NewGauge(sslChainExpiryInTimeStampGaugeOpts)
	probeSSLLastInformation := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "probe_ssl_last_chain_info",
			Help: "Contains SSL leaf certificate information",
		},
		[]string{"fingerprint_sha256", "subject", "issuer", "subjectalternative", "serialnumber"},
	)
	probeTLSVersion := prometheus.NewGaugeVec(
		probeTLSInfoGaugeOpts,
		[]string{"version"},
	)
	probeFailedDueToRegex := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_regex",
		Help: "Indicates if probe failed due to regex",
	})
	probeFailedDueToBytes := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_bytes",
		Help: "Indicates if probe failed due to bytes",
	})
	registry.MustRegister(probeFailedDueToRegex)
	registry.MustRegister(probeFailedDueToBytes)

	var queryResponses []config.QueryResponse
	var tlsConfig *pconfig.TLSConfig
	var useTLS bool

	switch proberName {
	case "tcp":
		queryResponses = module.TCP.QueryResponse
		tlsConfig = &module.TCP.TLSConfig
		useTLS = module.TCP.TLS
	case "unix":
		queryResponses = module.Unix.QueryResponse
		tlsConfig = &module.Unix.TLSConfig
		useTLS = module.Unix.TLS
	}

	// Pre-register probe_expect_info with the union of all label names so that
	// multiple query_response entries with different label sets do not cause a
	// duplicate-registration panic (see GitHub #1526).
	allLabelNames := queryResponseLabelNames(queryResponses)
	var probeExpectInfoVec *prometheus.GaugeVec
	if len(allLabelNames) > 0 {
		probeExpectInfoVec = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probe_expect_info",
				Help: "Explicit content matched",
			},
			allLabelNames,
		)
		registry.MustRegister(probeExpectInfoVec)
	}

	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		logger.Error("Error setting deadline", "err", err)
		return false
	}

	if useTLS {
		state := conn.(*tls.Conn).ConnectionState()
		registry.MustRegister(probeSSLEarliestCertExpiry, probeTLSVersion, probeSSLLastChainExpiryTimestampSeconds, probeSSLLastInformation)
		probeSSLEarliestCertExpiry.Set(float64(getEarliestCertExpiry(&state).Unix()))
		probeTLSVersion.WithLabelValues(getTLSVersion(&state)).Set(1)
		probeSSLLastChainExpiryTimestampSeconds.Set(float64(getLastChainExpiry(&state).Unix()))
		probeSSLLastInformation.WithLabelValues(getFingerprint(&state), getSubject(&state), getIssuer(&state), getDNSNames(&state), getSerialNumber(&state)).Set(1)
	}

	scanner := bufio.NewScanner(conn)
	for i, qr := range queryResponses {
		logger.Debug("Processing query response entry", "entry_number", i)
		send := qr.Send
		if qr.Expect.Regexp != nil {
			var match []int
			// Read lines until one of them matches the configured regexp.
			for scanner.Scan() {
				logger.Debug("Read line", "line", scanner.Text())
				match = qr.Expect.FindSubmatchIndex(scanner.Bytes())
				if match != nil {
					logger.Debug("Regexp matched", "regexp", qr.Expect.Regexp, "line", scanner.Text())
					break
				}
			}
			if scanner.Err() != nil {
				logger.Error("Error reading from connection", "err", scanner.Err().Error())
				return false
			}
			if match == nil {
				probeFailedDueToRegex.Set(1)
				logger.Error("Regexp did not match", "regexp", qr.Expect.Regexp, "line", scanner.Text())
				return false
			}
			probeFailedDueToRegex.Set(0)
			send = string(qr.Expect.Expand(nil, []byte(send), scanner.Bytes(), match))
			if qr.Labels != nil {
				probeExpectInfo(probeExpectInfoVec, allLabelNames, &qr, scanner.Bytes(), match)
			}
		}
		if qr.ExpectBytes != "" {
			expect_bytes := []byte(qr.ExpectBytes)

			// Try to read same number of bytes as expected.
			data := make([]byte, len(expect_bytes))
			n, err := conn.Read(data)
			if err != nil {
				logger.Error("Error reading from connection", "err", err)
				return false
			}

			logger.Debug("Read bytes", "bytes", data)

			if n < len(expect_bytes) {
				logger.Error("Read less data than expected", "expected", expect_bytes, "bytes", data)
				return false
			}

			if !bytes.Equal(expect_bytes, data) {
				probeFailedDueToBytes.Set(1)
				logger.Error("Bytes did not match", "expected", expect_bytes, "bytes", data)
				return false
			}
			logger.Debug("Bytes matched", "expected", expect_bytes, "bytes", data)
			probeFailedDueToBytes.Set(0)
		}
		if send != "" {
			logger.Debug("Sending line", "line", send)
			if _, err := fmt.Fprintf(conn, "%s\n", send); err != nil {
				logger.Error("Failed to send", "err", err)
				return false
			}
		}
		if qr.StartTLS {
			// Upgrade TCP connection to TLS.
			tlsUpgradeConfig, err := pconfig.NewTLSConfig(tlsConfig)
			if err != nil {
				logger.Error("Failed to create TLS configuration", "err", err)
				return false
			}
			if proberName == "tcp" && tlsUpgradeConfig.ServerName == "" {
				// Use target-hostname as default for TLS-servername.
				targetAddress, _, _ := net.SplitHostPort(target) // Had succeeded in dialTCP already.
				tlsUpgradeConfig.ServerName = targetAddress
			}

			tlsConn := tls.Client(conn, tlsUpgradeConfig)
			defer tlsConn.Close()

			// Initiate TLS handshake (required here to get TLS state).
			if err := tlsConn.Handshake(); err != nil {
				logger.Error("TLS Handshake (client) failed", "err", err)
				return false
			}
			logger.Debug("TLS Handshake (client) succeeded.")
			conn = net.Conn(tlsConn)
			scanner = bufio.NewScanner(conn)

			// Get certificate expiry.
			state := tlsConn.ConnectionState()
			registry.MustRegister(probeSSLEarliestCertExpiry, probeTLSVersion, probeSSLLastChainExpiryTimestampSeconds, probeSSLLastInformation)
			probeSSLEarliestCertExpiry.Set(float64(getEarliestCertExpiry(&state).Unix()))
			probeTLSVersion.WithLabelValues(getTLSVersion(&state)).Set(1)
			probeSSLLastChainExpiryTimestampSeconds.Set(float64(getLastChainExpiry(&state).Unix()))
			probeSSLLastInformation.WithLabelValues(getFingerprint(&state), getSubject(&state), getIssuer(&state), getDNSNames(&state), getSerialNumber(&state)).Set(1)
		}
	}
	return true
}
