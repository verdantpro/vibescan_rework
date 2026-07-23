package enrich

import (
	"testing"
	"time"
)

func TestParseInternetDB(t *testing.T) {
	body := []byte(`{"ip":"1.2.3.4","ports":[22,80,443,3306],"hostnames":["a.example.com"],
		"cpes":["cpe:/a:nginx:nginx"],"vulns":["CVE-2021-41773","CVE-2019-0211"],"tags":["database","cloud"]}`)
	rec, ok := parseInternetDB(body)
	if !ok {
		t.Fatal("expected parse ok")
	}
	if len(rec.Ports) != 4 || len(rec.Vulns) != 2 || len(rec.Tags) != 2 {
		t.Fatalf("unexpected record: %+v", rec)
	}
	if !rec.hasSource("internetdb") {
		t.Fatal("expected internetdb source")
	}
}

func TestParseShodanHost(t *testing.T) {
	body := []byte(`{"org":"DigitalOcean","isp":"DigitalOcean LLC","asn":"AS14061",
		"country_name":"United States","city":"Frankfurt","last_update":"2026-05-30T12:34:56.789012",
		"data":[{"port":80,"product":"nginx","version":"1.14.0"},{"port":22,"product":"OpenSSH","version":"8.2"}]}`)
	rec, ok := parseShodanHost(body)
	if !ok {
		t.Fatal("expected parse ok")
	}
	if rec.Org != "DigitalOcean" || rec.ASN != "AS14061" {
		t.Fatalf("ownership not parsed: %+v", rec)
	}
	if len(rec.Products) != 2 || rec.Products[0] != "nginx 1.14.0" {
		t.Fatalf("products not parsed: %+v", rec.Products)
	}
	if rec.LastSeen.IsZero() {
		t.Fatal("last_update not parsed")
	}
}

func TestMergeAndNormalize(t *testing.T) {
	rec := Record{IP: "1.2.3.4"}
	rec.merge(Record{Ports: []int{80, 22}, Vulns: []string{"CVE-2"}, Tags: []string{"b"}, Sources: []string{"internetdb"}})
	rec.merge(Record{Ports: []int{22, 3306}, Vulns: []string{"CVE-1", "CVE-2"}, Org: "Acme", Sources: []string{"shodan"}})
	rec.normalize()

	// ports deduped + sorted
	if got := rec.Ports; len(got) != 3 || got[0] != 22 || got[2] != 3306 {
		t.Fatalf("ports = %v", got)
	}
	// vulns deduped + sorted
	if got := rec.Vulns; len(got) != 2 || got[0] != "CVE-1" {
		t.Fatalf("vulns = %v", got)
	}
	if rec.Org != "Acme" {
		t.Fatalf("org = %q", rec.Org)
	}
	if !rec.hasSource("shodan") || !rec.hasSource("internetdb") {
		t.Fatalf("sources = %v", rec.Sources)
	}
}

func TestComputeVerdict(t *testing.T) {
	if v := computeVerdict(nil); v != "" {
		t.Fatalf("nil → %q, want empty", v)
	}
	// Keyless-only (geo/BGP, no reputation) must not emit a false 'clean'.
	if v := computeVerdict(&ThreatIntel{IPAPI: &IPAPIData{Country: "US"}}); v != "" {
		t.Fatalf("no reputation → %q, want empty", v)
	}
	// A reputation source with no findings → clean.
	if v := computeVerdict(&ThreatIntel{VirusTotal: &VTData{Harmless: 80}}); v != "clean" {
		t.Fatalf("harmless VT → %q, want clean", v)
	}
	// Suspicious escalation.
	if v := computeVerdict(&ThreatIntel{AbuseIPDB: &AbuseData{Confidence: 40}}); v != "suspicious" {
		t.Fatalf("abuse 40 → %q, want suspicious", v)
	}
	// Malicious escalation dominates.
	if v := computeVerdict(&ThreatIntel{
		OTX:        &OTXData{PulseCount: 3}, // would be suspicious alone
		VirusTotal: &VTData{Malicious: 5},   // malicious
	}); v != "malicious" {
		t.Fatalf("VT malicious → %q, want malicious", v)
	}
}

func TestFreshness(t *testing.T) {
	now := time.Now()
	rec := Record{Sources: []string{"internetdb"}, FetchedAt: now}

	e := NewEnricher(nil, Options{RPS: 1}) // no key
	if !e.fresh(rec, now, false) {
		t.Fatal("shallow record should be fresh for non-deep")
	}
	// Stale by age.
	if e.fresh(Record{Sources: []string{"internetdb"}, FetchedAt: now.Add(-200 * time.Hour)}, now, false) {
		t.Fatal("record older than the TTL should be stale")
	}
	// A deep request needs a fresh DeepFetchedAt regardless of key.
	if e.fresh(rec, now, true) {
		t.Fatal("deep request should refetch a record with no DeepFetchedAt")
	}
	deepRec := Record{Sources: []string{"internetdb", "shodan"}, FetchedAt: now, DeepFetchedAt: now}
	if !e.fresh(deepRec, now, true) {
		t.Fatal("fresh deep record should be reused")
	}
	// With a Shodan key, a deep request also needs a shodan-sourced record.
	ek := NewEnricher(nil, Options{ShodanKey: "KEY", RPS: 1})
	shallowDeep := Record{Sources: []string{"internetdb"}, FetchedAt: now, DeepFetchedAt: now}
	if ek.fresh(shallowDeep, now, true) {
		t.Fatal("keyed deep should refetch a record with no shodan source")
	}
}
