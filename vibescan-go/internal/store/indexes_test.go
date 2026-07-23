package store

import (
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

func TestTextWeightsEqual(t *testing.T) {
	want := map[string]int{"banner": 10, "geoip.city": 9, "fulltext": 1}

	// Mongo decodes weights as int32; an equal set (order-independent) matches.
	got := bson.M{"fulltext": int32(1), "banner": int32(10), "geoip.city": int32(9)}
	if !textWeightsEqual(got, want) {
		t.Fatal("identical weights should compare equal")
	}

	// A missing field (e.g. the old index without geo) must not match, so the
	// index gets dropped and rebuilt.
	old := bson.M{"banner": int32(10), "fulltext": int32(1)}
	if textWeightsEqual(old, want) {
		t.Fatal("weights with a different field set must not compare equal")
	}

	// Same fields, different weight → not equal.
	diff := bson.M{"banner": int32(5), "geoip.city": int32(9), "fulltext": int32(1)}
	if textWeightsEqual(diff, want) {
		t.Fatal("differing weight value must not compare equal")
	}
}

func TestToInt(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want int
	}{
		{int32(7), 7}, {int64(7), 7}, {int(7), 7}, {float64(7), 7}, {"nope", -1},
	} {
		if got := toInt(tc.in); got != tc.want {
			t.Errorf("toInt(%v)=%d want %d", tc.in, got, tc.want)
		}
	}
}
