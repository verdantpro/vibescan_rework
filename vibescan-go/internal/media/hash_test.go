package media

import "testing"

// Golden values below are produced by the Python implementations in
// vibescan_v2/common/shared_utils.py and common/r2_storage.py.

func TestCaptureHashExt(t *testing.T) {
	tests := []struct {
		in, wantHash, wantExt string
		wantOK                bool
	}{
		{"iVBORw0KGgoAAAA", "a147348632d4", "png", true},
		{"/9j/4AAQSkZJRg", "2b7379d5d31f", "jpg", true},
		{"screenshot_error: timeout", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range tests {
		h, e, ok := CaptureHashExt(tc.in)
		if h != tc.wantHash || e != tc.wantExt || ok != tc.wantOK {
			t.Errorf("CaptureHashExt(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.in, h, e, ok, tc.wantHash, tc.wantExt, tc.wantOK)
		}
	}
}

func TestDomStructureHash(t *testing.T) {
	in := "<html><body><h1>Hi</h1><!--c--><script>x</script></body></html>"
	const want = "2a08fec45568a314"
	if got := DomStructureHash(in); got != want {
		t.Errorf("DomStructureHash = %q, want %q", got, want)
	}
	if got := DomStructureHash("   "); got != "" {
		t.Errorf("DomStructureHash(blank) = %q, want empty", got)
	}
}

func TestExtractProduct(t *testing.T) {
	tests := map[string]string{
		"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0":                        "nginx",
		"Apache/2.4.1 (Unix)":                                            "Apache",
		"product: nginx version: 1.18.0 extrainfo: Ubuntu":               "nginx",
		"product: Squid http proxy version: 3.5.20":                      "Squid",
		"product: Amazon CloudFront httpd":                               "Amazon",
		"Server: cloudflare":                                             "cloudflare",
		"":                                                               "",
	}
	for in, want := range tests {
		if got := ExtractProduct(in); got != want {
			t.Errorf("ExtractProduct(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitPhashChunks(t *testing.T) {
	got := SplitPhashChunks("abcd1234ef567890")
	want := map[string]string{
		"phash_c0": "abcd", "phash_c1": "1234", "phash_c2": "ef56", "phash_c3": "7890",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("chunk %s = %q, want %q", k, got[k], v)
		}
	}
	if SplitPhashChunks("nothex") != nil {
		t.Error("expected nil for invalid pHash")
	}
}
