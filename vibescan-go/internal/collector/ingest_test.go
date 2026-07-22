package collector

import (
	"testing"
	"time"

	"github.com/vibescan/vibescan-go/internal/config"
)

func TestBuildEntryRedactsSubmitterWhenAnon(t *testing.T) {
	ing := NewIngestor(&config.Config{}, nil, nil, nil, nil)
	now := time.Now().UTC()
	h := host{Whois: "", Anon: false}
	svc := service{Banner: "nginx", Capture: ""}

	// no_report / batch anon → sentinel, not the real client IP.
	e := ing.buildEntry(h, svc, 0x01020304, "1.2.3.4", 80, now, true, "203.0.113.9", nil)
	if e.doc["submitted_by"] != AnonSubmittedBy {
		t.Fatalf("anon batch: submitted_by = %v, want %s", e.doc["submitted_by"], AnonSubmittedBy)
	}
	if e.doc["anon"] != true {
		t.Fatalf("anon batch: anon = %v, want true", e.doc["anon"])
	}

	// Per-host anon flag alone is enough.
	h.Anon = true
	e = ing.buildEntry(h, svc, 0x01020304, "1.2.3.4", 80, now, false, "203.0.113.9", nil)
	if e.doc["submitted_by"] != AnonSubmittedBy {
		t.Fatalf("host anon: submitted_by = %v, want %s", e.doc["submitted_by"], AnonSubmittedBy)
	}

	// Attributed path keeps the real client IP.
	h.Anon = false
	e = ing.buildEntry(h, svc, 0x01020304, "1.2.3.4", 80, now, false, "203.0.113.9", nil)
	if e.doc["submitted_by"] != "203.0.113.9" {
		t.Fatalf("attributed: submitted_by = %v, want 203.0.113.9", e.doc["submitted_by"])
	}
	if e.doc["anon"] != false {
		t.Fatalf("attributed: anon = %v, want false", e.doc["anon"])
	}
}
