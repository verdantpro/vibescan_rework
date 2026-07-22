package store

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DefaultBlacklistSeed mirrors common/nettools.py:DEFAULT_BLACKLIST_SEED. It is
// the reserved/documentation/private ranges the collector seeds and serves when
// the database is empty or unavailable.
var DefaultBlacklistSeed = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
}

// SeedBlacklist ensures the blacklist collection has a unique cidr index and,
// if empty, inserts the default seed, mirroring server.py:ensure_blacklist_seed.
func (m *Mongo) SeedBlacklist(ctx context.Context) error {
	if m == nil || m.blacklist == nil {
		return nil
	}
	_, _ = m.blacklist.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "cidr", Value: 1}},
		Options: options.Index().SetUnique(true),
	})

	n, err := m.blacklist.EstimatedDocumentCount(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}

	models := make([]mongo.WriteModel, 0, len(DefaultBlacklistSeed))
	for _, cidr := range DefaultBlacklistSeed {
		models = append(models, mongo.NewUpdateOneModel().
			SetFilter(bson.M{"cidr": cidr}).
			SetUpdate(bson.M{"$set": bson.M{"cidr": cidr, "enabled": true}}).
			SetUpsert(true))
	}
	_, err = m.blacklist.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false))
	return err
}

// ReadBlacklistCIDRs returns all enabled CIDRs, mirroring the query in
// server.py:_get_blacklist_cidrs. It returns (nil, error) when unavailable so
// the caller can fall back to the seed list.
func (m *Mongo) ReadBlacklistCIDRs(ctx context.Context) ([]string, error) {
	if m == nil || m.blacklist == nil {
		return nil, mongo.ErrClientDisconnected
	}
	cur, err := m.blacklist.Find(ctx,
		bson.M{"enabled": bson.M{"$ne": false}},
		options.Find().SetProjection(bson.M{"cidr": 1}),
	)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var out []string
	for cur.Next(ctx) {
		var doc struct {
			CIDR string `bson:"cidr"`
		}
		if err := cur.Decode(&doc); err != nil {
			continue
		}
		if doc.CIDR != "" {
			out = append(out, doc.CIDR)
		}
	}
	return out, cur.Err()
}
