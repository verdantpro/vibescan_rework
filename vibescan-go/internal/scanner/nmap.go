package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
)

// nmapRun mirrors the parts of nmap's -oX XML we consume.
type nmapRun struct {
	Hosts []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports struct {
			Ports []struct {
				PortID int    `xml:"portid,attr"`
				Proto  string `xml:"protocol,attr"`
				State  struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name      string `xml:"name,attr"`
					Product   string `xml:"product,attr"`
					Version   string `xml:"version,attr"`
					ExtraInfo string `xml:"extrainfo,attr"`
					Tunnel    string `xml:"tunnel,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// ParseNmapXML parses `nmap -oX -` output into ip → port → banner for open
// services, mirroring client_agent.py:_scan_hosts.
func ParseNmapXML(data []byte) (map[string]map[int]string, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}
	out := map[string]map[int]string{}
	for _, h := range run.Hosts {
		ip := ""
		for _, a := range h.Addresses {
			if a.Type == "ipv4" {
				ip = a.Addr
				break
			}
		}
		if ip == "" {
			continue
		}
		ports := map[int]string{}
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			ports[p.PortID] = serviceBanner(p.Service.Product, p.Service.Version, p.Service.ExtraInfo, p.Service.Name)
		}
		if len(ports) > 0 {
			out[ip] = ports
		}
	}
	return out, nil
}

// serviceBanner formats the nmap service fields as a "key: value" banner
// compatible with extract_product / stats banner-cleaning downstream.
func serviceBanner(product, version, extrainfo, name string) string {
	var parts []string
	if product != "" {
		parts = append(parts, "product: "+product)
	}
	if version != "" {
		parts = append(parts, "version: "+version)
	}
	if extrainfo != "" {
		parts = append(parts, "extrainfo: "+extrainfo)
	}
	if len(parts) == 0 && name != "" {
		parts = append(parts, name)
	}
	return strings.Join(parts, " ")
}

// RunNmap executes `nmap -sV <opts> -oX - -p <ports> <ips>` and returns parsed
// open services. -sV is always included. The context bounds the run time; a
// killed/timed-out scan reaps cleanly via exec's process handling.
func RunNmap(ctx context.Context, ips, ports []string, extraOpts string) (map[string]map[int]string, error) {
	args := []string{"-sV"}
	for _, o := range strings.Fields(extraOpts) {
		if o != "-sV" {
			args = append(args, o)
		}
	}
	args = append(args, "-oX", "-", "-p", strings.Join(ports, ","))
	args = append(args, ips...)

	cmd := exec.CommandContext(ctx, "nmap", args...)
	out, err := cmd.Output()
	// nmap exits 0 (ok) or 1 (some hosts down); both may still carry XML.
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 && len(out) > 0 {
			// fall through to parse
		} else {
			return nil, fmt.Errorf("nmap failed: %w", err)
		}
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, fmt.Errorf("nmap produced no output")
	}
	return ParseNmapXML(out)
}
