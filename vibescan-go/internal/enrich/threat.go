package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ThreatIntel mirrors scope-recon's per-source model (minus the AI narrative).
// Each field is nil when its source didn't run (missing key) or had no data.
type ThreatIntel struct {
	IPAPI      *IPAPIData     `json:"ipapi,omitempty" bson:"ipapi,omitempty"`
	BGP        *BGPData       `json:"bgp,omitempty" bson:"bgp,omitempty"`
	AbuseIPDB  *AbuseData     `json:"abuseipdb,omitempty" bson:"abuseipdb,omitempty"`
	VirusTotal *VTData        `json:"virustotal,omitempty" bson:"virustotal,omitempty"`
	GreyNoise  *GreyNoiseData `json:"greynoise,omitempty" bson:"greynoise,omitempty"`
	OTX        *OTXData       `json:"otx,omitempty" bson:"otx,omitempty"`
	ThreatFox  *ThreatFoxData `json:"threatfox,omitempty" bson:"threatfox,omitempty"`
	IPQS       *IPQSData      `json:"ipqs,omitempty" bson:"ipqs,omitempty"`
	Pulsedive  *PulsediveData `json:"pulsedive,omitempty" bson:"pulsedive,omitempty"`
	IPInfo     *IPInfoData    `json:"ipinfo,omitempty" bson:"ipinfo,omitempty"`
}

func (t *ThreatIntel) empty() bool {
	return t == nil || (t.IPAPI == nil && t.BGP == nil && t.AbuseIPDB == nil && t.VirusTotal == nil &&
		t.GreyNoise == nil && t.OTX == nil && t.ThreatFox == nil && t.IPQS == nil &&
		t.Pulsedive == nil && t.IPInfo == nil)
}

type IPAPIData struct {
	Country string `json:"country,omitempty" bson:"country,omitempty"`
	Region  string `json:"region,omitempty" bson:"region,omitempty"`
	City    string `json:"city,omitempty" bson:"city,omitempty"`
	ISP     string `json:"isp,omitempty" bson:"isp,omitempty"`
	Org     string `json:"org,omitempty" bson:"org,omitempty"`
	ASN     string `json:"asn,omitempty" bson:"asn,omitempty"`
}

type BGPData struct {
	ASN      int      `json:"asn,omitempty" bson:"asn,omitempty"`
	ASNName  string   `json:"asn_name,omitempty" bson:"asn_name,omitempty"`
	ASNDesc  string   `json:"asn_description,omitempty" bson:"asn_description,omitempty"`
	RIR      string   `json:"rir,omitempty" bson:"rir,omitempty"`
	Prefixes []string `json:"prefixes,omitempty" bson:"prefixes,omitempty"`
}

type AbuseData struct {
	Confidence     int    `json:"abuse_confidence" bson:"abuse_confidence"`
	TotalReports   int    `json:"total_reports" bson:"total_reports"`
	Country        string `json:"country,omitempty" bson:"country,omitempty"`
	Domain         string `json:"domain,omitempty" bson:"domain,omitempty"`
	ISP            string `json:"isp,omitempty" bson:"isp,omitempty"`
	UsageType      string `json:"usage_type,omitempty" bson:"usage_type,omitempty"`
	LastReportedAt string `json:"last_reported_at,omitempty" bson:"last_reported_at,omitempty"`
	IsTor          bool   `json:"is_tor" bson:"is_tor"`
	IsWhitelisted  bool   `json:"is_whitelisted" bson:"is_whitelisted"`
}

type VTData struct {
	Malicious        int    `json:"malicious" bson:"malicious"`
	Suspicious       int    `json:"suspicious" bson:"suspicious"`
	Harmless         int    `json:"harmless" bson:"harmless"`
	Undetected       int    `json:"undetected" bson:"undetected"`
	LastAnalysisDate string `json:"last_analysis_date,omitempty" bson:"last_analysis_date,omitempty"`
}

type GreyNoiseData struct {
	Noise          bool   `json:"noise" bson:"noise"`
	Riot           bool   `json:"riot" bson:"riot"`
	Classification string `json:"classification,omitempty" bson:"classification,omitempty"`
	Name           string `json:"name,omitempty" bson:"name,omitempty"`
	LastSeen       string `json:"last_seen,omitempty" bson:"last_seen,omitempty"`
}

type OTXData struct {
	PulseCount int      `json:"pulse_count" bson:"pulse_count"`
	PulseNames []string `json:"pulse_names,omitempty" bson:"pulse_names,omitempty"`
}

type ThreatFoxData struct {
	IOCCount int            `json:"ioc_count" bson:"ioc_count"`
	IOCs     []ThreatFoxIOC `json:"iocs,omitempty" bson:"iocs,omitempty"`
}

type ThreatFoxIOC struct {
	IOC        string `json:"ioc" bson:"ioc"`
	ThreatType string `json:"threat_type,omitempty" bson:"threat_type,omitempty"`
	Malware    string `json:"malware,omitempty" bson:"malware,omitempty"`
	Confidence int    `json:"confidence_level" bson:"confidence_level"`
	FirstSeen  string `json:"first_seen,omitempty" bson:"first_seen,omitempty"`
	LastSeen   string `json:"last_seen,omitempty" bson:"last_seen,omitempty"`
}

type IPQSData struct {
	FraudScore    int    `json:"fraud_score" bson:"fraud_score"`
	Proxy         bool   `json:"proxy" bson:"proxy"`
	VPN           bool   `json:"vpn" bson:"vpn"`
	Tor           bool   `json:"tor" bson:"tor"`
	Bot           bool   `json:"bot_status" bson:"bot_status"`
	RecentAbuse   bool   `json:"recent_abuse" bson:"recent_abuse"`
	AbuseVelocity string `json:"abuse_velocity,omitempty" bson:"abuse_velocity,omitempty"`
	ISP           string `json:"isp,omitempty" bson:"isp,omitempty"`
	CountryCode   string `json:"country_code,omitempty" bson:"country_code,omitempty"`
}

type PulsediveData struct {
	Risk     string   `json:"risk,omitempty" bson:"risk,omitempty"`
	LastSeen string   `json:"last_seen,omitempty" bson:"last_seen,omitempty"`
	Threats  []string `json:"threats,omitempty" bson:"threats,omitempty"`
	Feeds    []string `json:"feeds,omitempty" bson:"feeds,omitempty"`
}

type IPInfoData struct {
	Hostname  string `json:"hostname,omitempty" bson:"hostname,omitempty"`
	City      string `json:"city,omitempty" bson:"city,omitempty"`
	Region    string `json:"region,omitempty" bson:"region,omitempty"`
	Country   string `json:"country,omitempty" bson:"country,omitempty"`
	Org       string `json:"org,omitempty" bson:"org,omitempty"`
	Timezone  string `json:"timezone,omitempty" bson:"timezone,omitempty"`
	IsVPN     bool   `json:"is_vpn" bson:"is_vpn"`
	IsProxy   bool   `json:"is_proxy" bson:"is_proxy"`
	IsTor     bool   `json:"is_tor" bson:"is_tor"`
	IsHosting bool   `json:"is_hosting" bson:"is_hosting"`
}

// fanOutThreat runs the keyed reputation/threat sources concurrently (each a
// distinct API, so no shared throttle) and writes results into t. Bounded by a
// per-fan-out timeout so one slow vendor can't hang the request.
func (e *Enricher) fanOutThreat(ctx context.Context, ip string, t *ThreatIntel) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex
	jobs := []func(){
		func() {
			if d, ok := e.virusTotal(ctx, ip); ok {
				mu.Lock()
				t.VirusTotal = d
				mu.Unlock()
			}
		},
		func() {
			if d, ok := e.abuseIPDB(ctx, ip); ok {
				mu.Lock()
				t.AbuseIPDB = d
				mu.Unlock()
			}
		},
		func() {
			if d, ok := e.greyNoise(ctx, ip); ok {
				mu.Lock()
				t.GreyNoise = d
				mu.Unlock()
			}
		},
		func() {
			if d, ok := e.otx(ctx, ip); ok {
				mu.Lock()
				t.OTX = d
				mu.Unlock()
			}
		},
		func() {
			if d, ok := e.threatFox(ctx, ip); ok {
				mu.Lock()
				t.ThreatFox = d
				mu.Unlock()
			}
		},
		func() {
			if d, ok := e.ipqs(ctx, ip); ok {
				mu.Lock()
				t.IPQS = d
				mu.Unlock()
			}
		},
		func() {
			if d, ok := e.pulsedive(ctx, ip); ok {
				mu.Lock()
				t.Pulsedive = d
				mu.Unlock()
			}
		},
		func() {
			if d, ok := e.ipinfo(ctx, ip); ok {
				mu.Lock()
				t.IPInfo = d
				mu.Unlock()
			}
		},
	}
	for _, j := range jobs {
		wg.Add(1)
		go func(j func()) { defer wg.Done(); j() }(j)
	}
	wg.Wait()
}

// computeVerdict ports scope-recon's output.rs thresholds. Returns "" (unknown)
// when no reputation source ran — so the keyless worker never emits a false
// "clean".
func computeVerdict(t *ThreatIntel) string {
	if t == nil {
		return ""
	}
	hasRep := t.VirusTotal != nil || t.AbuseIPDB != nil || t.GreyNoise != nil || t.OTX != nil ||
		t.ThreatFox != nil || t.IPQS != nil || t.Pulsedive != nil
	if !hasRep {
		return ""
	}
	sev := 0
	if t.ThreatFox != nil && t.ThreatFox.IOCCount > 0 {
		sev = 2
	}
	if t.VirusTotal != nil && t.VirusTotal.Malicious > 0 {
		sev = 2
	}
	if t.AbuseIPDB != nil && t.AbuseIPDB.Confidence >= 75 {
		sev = 2
	}
	if t.GreyNoise != nil && t.GreyNoise.Classification == "malicious" {
		sev = 2
	}
	if t.IPQS != nil && t.IPQS.FraudScore >= 75 {
		sev = 2
	}
	if t.Pulsedive != nil && (t.Pulsedive.Risk == "critical" || t.Pulsedive.Risk == "high") {
		sev = 2
	}
	if sev < 1 {
		if t.VirusTotal != nil && t.VirusTotal.Suspicious > 0 {
			sev = 1
		}
		if t.AbuseIPDB != nil && t.AbuseIPDB.Confidence >= 25 {
			sev = 1
		}
		if t.OTX != nil && t.OTX.PulseCount > 0 {
			sev = 1
		}
		if t.IPQS != nil && t.IPQS.FraudScore >= 30 {
			sev = 1
		}
		if t.Pulsedive != nil && t.Pulsedive.Risk == "medium" {
			sev = 1
		}
	}
	switch sev {
	case 2:
		return "malicious"
	case 1:
		return "suspicious"
	default:
		return "clean"
	}
}

// --- keyless sources (throttled; also used by the worker) ---

func (e *Enricher) ipAPI(ctx context.Context, ip string) (*IPAPIData, bool) {
	if err := e.lim.wait(ctx); err != nil {
		return nil, false
	}
	u := "http://ip-api.com/json/" + url.PathEscape(ip) + "?fields=status,message,country,regionName,city,isp,org,as"
	body, status, ok := e.fetch(ctx, u, nil)
	if !ok || status != http.StatusOK {
		return nil, false
	}
	var d struct {
		Status     string `json:"status"`
		Country    string `json:"country"`
		RegionName string `json:"regionName"`
		City       string `json:"city"`
		ISP        string `json:"isp"`
		Org        string `json:"org"`
		As         string `json:"as"`
	}
	if json.Unmarshal(body, &d) != nil || d.Status != "success" {
		return nil, false
	}
	return &IPAPIData{Country: d.Country, Region: d.RegionName, City: d.City, ISP: d.ISP, Org: d.Org, ASN: d.As}, true
}

func (e *Enricher) bgp(ctx context.Context, ip string) (*BGPData, bool) {
	if err := e.lim.wait(ctx); err != nil {
		return nil, false
	}
	u := "https://stat.ripe.net/data/prefix-overview/data.json?resource=" + url.QueryEscape(ip)
	body, status, ok := e.fetch(ctx, u, nil)
	if !ok || status != http.StatusOK {
		return nil, false
	}
	var d struct {
		Data struct {
			Resource string `json:"resource"`
			Asns     []struct {
				Asn    int    `json:"asn"`
				Holder string `json:"holder"`
			} `json:"asns"`
			Block struct {
				Desc string `json:"desc"`
			} `json:"block"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &d) != nil {
		return nil, false
	}
	out := &BGPData{}
	if d.Data.Resource != "" {
		out.Prefixes = []string{d.Data.Resource}
	}
	if len(d.Data.Asns) > 0 {
		out.ASN = d.Data.Asns[0].Asn
		name, desc, found := strings.Cut(d.Data.Asns[0].Holder, " - ")
		out.ASNName = strings.TrimSpace(name)
		if found {
			out.ASNDesc = strings.TrimSpace(desc)
		}
	}
	// The RIR is the last token of the block description ("Administered by ARIN"),
	// but only when it's actually one of the five registries — otherwise the
	// heuristic picks up noise like "Space" or "ALLOCATED".
	for _, tok := range strings.Fields(d.Data.Block.Desc) {
		switch strings.ToUpper(strings.Trim(tok, "().,;")) {
		case "ARIN", "RIPE", "APNIC", "LACNIC", "AFRINIC":
			out.RIR = strings.ToUpper(strings.Trim(tok, "().,;"))
		}
	}
	if out.ASN == 0 && len(out.Prefixes) == 0 {
		return nil, false
	}
	return out, true
}

// --- keyed sources (on-demand fan-out) ---

func (e *Enricher) virusTotal(ctx context.Context, ip string) (*VTData, bool) {
	if e.opt.VirusTotalKey == "" {
		return nil, false
	}
	u := "https://www.virustotal.com/api/v3/ip_addresses/" + url.PathEscape(ip)
	body, status, ok := e.fetch(ctx, u, map[string]string{"x-apikey": e.opt.VirusTotalKey})
	if !ok || status != http.StatusOK {
		return nil, false
	}
	var d struct {
		Data struct {
			Attributes struct {
				Stats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				LastAnalysisDate int64 `json:"last_analysis_date"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &d) != nil {
		return nil, false
	}
	a := d.Data.Attributes
	out := &VTData{Malicious: a.Stats.Malicious, Suspicious: a.Stats.Suspicious, Harmless: a.Stats.Harmless, Undetected: a.Stats.Undetected}
	if a.LastAnalysisDate > 0 {
		out.LastAnalysisDate = time.Unix(a.LastAnalysisDate, 0).UTC().Format("2006-01-02")
	}
	return out, true
}

func (e *Enricher) abuseIPDB(ctx context.Context, ip string) (*AbuseData, bool) {
	if e.opt.AbuseIPDBKey == "" {
		return nil, false
	}
	u := "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=" + url.QueryEscape(ip)
	body, status, ok := e.fetch(ctx, u, map[string]string{"Key": e.opt.AbuseIPDBKey, "Accept": "application/json"})
	if !ok || status != http.StatusOK {
		return nil, false
	}
	var d struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			TotalReports         int    `json:"totalReports"`
			CountryCode          string `json:"countryCode"`
			Domain               string `json:"domain"`
			ISP                  string `json:"isp"`
			UsageType            string `json:"usageType"`
			LastReportedAt       string `json:"lastReportedAt"`
			IsTor                bool   `json:"isTor"`
			IsWhitelisted        *bool  `json:"isWhitelisted"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &d) != nil {
		return nil, false
	}
	dd := d.Data
	out := &AbuseData{
		Confidence: dd.AbuseConfidenceScore, TotalReports: dd.TotalReports, Country: dd.CountryCode,
		Domain: dd.Domain, ISP: dd.ISP, UsageType: dd.UsageType, LastReportedAt: first10(dd.LastReportedAt),
		IsTor: dd.IsTor, IsWhitelisted: dd.IsWhitelisted != nil && *dd.IsWhitelisted,
	}
	return out, true
}

func (e *Enricher) greyNoise(ctx context.Context, ip string) (*GreyNoiseData, bool) {
	if e.opt.GreyNoiseKey == "" {
		return nil, false
	}
	u := "https://api.greynoise.io/v3/community/" + url.PathEscape(ip)
	body, status, ok := e.fetch(ctx, u, map[string]string{"Accept": "application/json", "key": e.opt.GreyNoiseKey})
	if !ok {
		return nil, false
	}
	if status == http.StatusNotFound {
		return &GreyNoiseData{Classification: "not seen"}, true
	}
	if status != http.StatusOK {
		return nil, false
	}
	var d struct {
		Noise          bool   `json:"noise"`
		Riot           bool   `json:"riot"`
		Classification string `json:"classification"`
		Name           string `json:"name"`
		LastSeen       string `json:"last_seen"`
	}
	if json.Unmarshal(body, &d) != nil {
		return nil, false
	}
	if d.Classification == "" {
		d.Classification = "unknown"
	}
	return &GreyNoiseData{Noise: d.Noise, Riot: d.Riot, Classification: d.Classification, Name: d.Name, LastSeen: d.LastSeen}, true
}

func (e *Enricher) otx(ctx context.Context, ip string) (*OTXData, bool) {
	if e.opt.OTXKey == "" {
		return nil, false
	}
	u := "https://otx.alienvault.com/api/v1/indicators/IPv4/" + url.PathEscape(ip) + "/general"
	body, status, ok := e.fetch(ctx, u, map[string]string{"X-OTX-API-KEY": e.opt.OTXKey})
	if !ok || status != http.StatusOK {
		return nil, false
	}
	var d struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Name string `json:"name"`
			} `json:"pulses"`
		} `json:"pulse_info"`
	}
	if json.Unmarshal(body, &d) != nil {
		return nil, false
	}
	out := &OTXData{PulseCount: d.PulseInfo.Count}
	for _, p := range d.PulseInfo.Pulses {
		if p.Name != "" {
			out.PulseNames = append(out.PulseNames, p.Name)
		}
	}
	return out, true
}

func (e *Enricher) threatFox(ctx context.Context, ip string) (*ThreatFoxData, bool) {
	if e.opt.ThreatFoxKey == "" {
		return nil, false
	}
	reqBody, _ := json.Marshal(map[string]any{"query": "search_ioc", "search_term": ip, "exact_match": true})
	body, status, ok := e.postJSON(ctx, "https://threatfox-api.abuse.ch/api/v1/", reqBody, map[string]string{"Auth-Key": e.opt.ThreatFoxKey})
	if !ok || status != http.StatusOK {
		return nil, false
	}
	var d struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			IOC        string `json:"ioc"`
			ThreatType string `json:"threat_type"`
			Malware    string `json:"malware_printable"`
			Confidence int    `json:"confidence_level"`
			FirstSeen  string `json:"first_seen"`
			LastSeen   string `json:"last_seen"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &d) != nil || d.QueryStatus != "ok" {
		// no_results / unknown_auth_key → treat as no IOCs.
		return &ThreatFoxData{IOCCount: 0}, d.QueryStatus == "no_results"
	}
	out := &ThreatFoxData{IOCCount: len(d.Data)}
	for _, r := range d.Data {
		out.IOCs = append(out.IOCs, ThreatFoxIOC{
			IOC: r.IOC, ThreatType: r.ThreatType, Malware: r.Malware,
			Confidence: r.Confidence, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen,
		})
	}
	return out, true
}

func (e *Enricher) ipqs(ctx context.Context, ip string) (*IPQSData, bool) {
	if e.opt.IPQSKey == "" {
		return nil, false
	}
	u := "https://ipqualityscore.com/api/json/ip/" + url.PathEscape(e.opt.IPQSKey) + "/" + url.PathEscape(ip)
	body, status, ok := e.fetch(ctx, u, nil)
	if !ok || status != http.StatusOK {
		return nil, false
	}
	var d struct {
		Success       bool   `json:"success"`
		FraudScore    int    `json:"fraud_score"`
		Proxy         bool   `json:"proxy"`
		VPN           bool   `json:"vpn"`
		Tor           bool   `json:"tor"`
		BotStatus     bool   `json:"bot_status"`
		RecentAbuse   bool   `json:"recent_abuse"`
		AbuseVelocity string `json:"abuse_velocity"`
		ISP           string `json:"ISP"`
		CountryCode   string `json:"country_code"`
	}
	if json.Unmarshal(body, &d) != nil || !d.Success {
		return nil, false
	}
	av := d.AbuseVelocity
	if av == "" {
		av = "none"
	}
	return &IPQSData{
		FraudScore: d.FraudScore, Proxy: d.Proxy, VPN: d.VPN, Tor: d.Tor, Bot: d.BotStatus,
		RecentAbuse: d.RecentAbuse, AbuseVelocity: av, ISP: d.ISP, CountryCode: d.CountryCode,
	}, true
}

func (e *Enricher) pulsedive(ctx context.Context, ip string) (*PulsediveData, bool) {
	if e.opt.PulsediveKey == "" {
		return nil, false
	}
	u := "https://pulsedive.com/api/info.php?pretty=1&ioc=" + url.QueryEscape(ip) + "&key=" + url.QueryEscape(e.opt.PulsediveKey)
	body, status, ok := e.fetch(ctx, u, nil)
	if !ok {
		return nil, false
	}
	if status == http.StatusNotFound {
		return &PulsediveData{Risk: "unknown"}, true
	}
	if status != http.StatusOK {
		return nil, false
	}
	var d struct {
		Risk      string `json:"risk"`
		StampSeen string `json:"stamp_seen"`
		Threats   []struct {
			Name string `json:"name"`
		} `json:"threats"`
		Feeds []struct {
			Name string `json:"name"`
		} `json:"feeds"`
	}
	if json.Unmarshal(body, &d) != nil {
		return &PulsediveData{Risk: "unknown"}, true
	}
	out := &PulsediveData{Risk: d.Risk, LastSeen: first10(d.StampSeen)}
	if out.Risk == "" {
		out.Risk = "unknown"
	}
	for _, x := range d.Threats {
		if x.Name != "" {
			out.Threats = append(out.Threats, x.Name)
		}
	}
	for _, x := range d.Feeds {
		if x.Name != "" {
			out.Feeds = append(out.Feeds, x.Name)
		}
	}
	return out, true
}

func (e *Enricher) ipinfo(ctx context.Context, ip string) (*IPInfoData, bool) {
	if e.opt.IPInfoToken == "" {
		return nil, false
	}
	u := "https://ipinfo.io/" + url.PathEscape(ip) + "/json?token=" + url.QueryEscape(e.opt.IPInfoToken)
	body, status, ok := e.fetch(ctx, u, nil)
	if !ok || status != http.StatusOK {
		return nil, false
	}
	var d struct {
		Hostname string `json:"hostname"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Org      string `json:"org"`
		Timezone string `json:"timezone"`
		Privacy  *struct {
			VPN     bool `json:"vpn"`
			Proxy   bool `json:"proxy"`
			Tor     bool `json:"tor"`
			Hosting bool `json:"hosting"`
		} `json:"privacy"`
	}
	if json.Unmarshal(body, &d) != nil {
		return nil, false
	}
	out := &IPInfoData{Hostname: d.Hostname, City: d.City, Region: d.Region, Country: d.Country, Org: d.Org, Timezone: d.Timezone}
	if d.Privacy != nil {
		out.IsVPN, out.IsProxy, out.IsTor, out.IsHosting = d.Privacy.VPN, d.Privacy.Proxy, d.Privacy.Tor, d.Privacy.Hosting
	}
	return out, true
}

// postJSON performs a bounded POST with a JSON body (ThreatFox).
func (e *Enricher) postJSON(ctx context.Context, u string, body []byte, headers map[string]string) ([]byte, int, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, 0, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, 0, false
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, resp.StatusCode, false
	}
	return b, resp.StatusCode, true
}

func first10(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 10 {
		return s[:10]
	}
	return s
}
