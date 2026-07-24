package httpapi

import (
	"testing"
	"time"

	"github.com/vibescan/vibescan-go/internal/config"
	"github.com/vibescan/vibescan-go/internal/store"
)

func TestToTileSurfacesEnrichmentProvenanceAndThumb(t *testing.T) {
	s := &Server{cfg: &config.Config{R2PublicURL: "https://cdn.example"}}
	enrichedAt := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	d := store.ServiceDoc{
		IPStr:      "203.0.113.7",
		Port:       443,
		Capture:    "r2:2/2/203.0.113.7-443.png",
		Thumb:      "r2:thumb/2/2/203.0.113.7-443.jpg",
		VulnCount:  3,
		ShodanTags: []string{"cloud"},
		Verdict:    "malicious",
		Sources:    []string{"internetdb", "shodan"},
		EnrichedAt: enrichedAt,
		UpdatedAt:  enrichedAt,
	}

	tile := s.toTile(d)

	if tile.ImageURL != "https://cdn.example/2/2/203.0.113.7-443.png" {
		t.Errorf("image_url = %q", tile.ImageURL)
	}
	if tile.ThumbURL != "https://cdn.example/thumb/2/2/203.0.113.7-443.jpg" {
		t.Errorf("thumb_url = %q", tile.ThumbURL)
	}
	if tile.EnrichedAt != enrichedAt.Format(time.RFC3339) {
		t.Errorf("enriched_at = %q, want %q", tile.EnrichedAt, enrichedAt.Format(time.RFC3339))
	}
	if len(tile.Sources) != 2 || tile.Sources[0] != "internetdb" {
		t.Errorf("sources = %v", tile.Sources)
	}
}

func TestToTileWithoutThumbOrEnrichment(t *testing.T) {
	s := &Server{cfg: &config.Config{R2PublicURL: "https://cdn.example"}}
	d := store.ServiceDoc{
		IPStr:   "203.0.113.8",
		Port:    80,
		Capture: "r2:2/2/203.0.113.8-80.png",
		// No Thumb, no EnrichedAt.
	}
	tile := s.toTile(d)
	if tile.ThumbURL != "" {
		t.Errorf("thumb_url = %q, want empty (no thumb → UI falls back to full image)", tile.ThumbURL)
	}
	if tile.EnrichedAt != "" {
		t.Errorf("enriched_at = %q, want empty", tile.EnrichedAt)
	}
}
