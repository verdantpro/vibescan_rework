// Package store holds the persistence adapters (MongoDB, R2, disk buffer)
// used by the collector.
package store

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"github.com/vibescan/vibescan-go/internal/config"
)

// UpsertOp is a single (ip, port) service upsert. Doc is the full $set body
// (already containing updated_at); the deterministic _id and received_at are
// applied via $setOnInsert at write time.
type UpsertOp struct {
	IPInt      int64          `bson:"ip_int"`
	Port       int            `bson:"port"`
	IPStr      string         `bson:"ip_str"`
	ReceivedAt time.Time      `bson:"received_at"`
	Doc        map[string]any `bson:"doc"`
}

// Mongo wraps the results and blacklist collections. When MongoDB is
// unreachable at startup the collections are nil and Available reports false;
// the collector then buffers writes to disk.
type Mongo struct {
	client     *mongo.Client
	results    *mongo.Collection
	blacklist  *mongo.Collection
	enrichment *mongo.Collection
}

// Connect dials MongoDB and pings it. It always returns a non-nil *Mongo; the
// error is non-nil (and collections nil) when the server is unreachable, so the
// collector can still start and buffer.
func Connect(ctx context.Context, cfg *config.Config) (*Mongo, error) {
	opts := options.Client().
		ApplyURI(cfg.MongoURI).
		SetReadPreference(readpref.Primary()).
		SetServerSelectionTimeout(3 * time.Second).
		SetMaxPoolSize(20)

	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return &Mongo{}, err
	}

	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx, readpref.Primary()); err != nil {
		_ = client.Disconnect(context.Background())
		return &Mongo{}, err
	}

	db := client.Database(cfg.MongoDB)
	return &Mongo{
		client:     client,
		results:    db.Collection(cfg.ResultsCollection),
		blacklist:  db.Collection(cfg.BlacklistCollection),
		enrichment: db.Collection(cfg.EnrichmentCollection),
	}, nil
}

// Available reports whether writes can be attempted.
func (m *Mongo) Available() bool { return m != nil && m.results != nil }

// Disconnect closes the client.
func (m *Mongo) Disconnect(ctx context.Context) {
	if m != nil && m.client != nil {
		_ = m.client.Disconnect(ctx)
	}
}

// deterministicID mirrors server.py: ObjectId(md5("ip:port")[:24]). This keeps
// upserts idempotent against documents written by the Python collector.
func deterministicID(ipInt int64, port int) (primitive.ObjectID, error) {
	sum := md5.Sum([]byte(fmt.Sprintf("%d:%d", ipInt, port)))
	return primitive.ObjectIDFromHex(hex.EncodeToString(sum[:])[:24])
}

// BulkUpsert writes ops as unordered upserts keyed by (ip, port). It returns
// the set of op indices that failed, allowing the caller to buffer only those.
func (m *Mongo) BulkUpsert(ctx context.Context, ops []UpsertOp) (failed map[int]bool, err error) {
	if len(ops) == 0 {
		return nil, nil
	}
	models := make([]mongo.WriteModel, 0, len(ops))
	for _, op := range ops {
		id, idErr := deterministicID(op.IPInt, op.Port)
		if idErr != nil {
			continue
		}
		models = append(models, mongo.NewUpdateOneModel().
			SetFilter(bson.M{"ip": op.IPInt, "port": op.Port}).
			SetUpdate(bson.M{
				"$set": op.Doc,
				"$setOnInsert": bson.M{
					"received_at": op.ReceivedAt,
					"_id":         id,
				},
			}).
			SetUpsert(true))
	}
	if len(models) == 0 {
		return nil, nil
	}

	_, err = m.results.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false))
	if err == nil {
		return nil, nil
	}

	// On partial failure, report which indices failed so the rest count as stored.
	if bwe, ok := err.(mongo.BulkWriteException); ok {
		failed = make(map[int]bool, len(bwe.WriteErrors))
		for _, we := range bwe.WriteErrors {
			failed[we.Index] = true
		}
		return failed, err
	}
	// Total failure: mark everything failed.
	failed = make(map[int]bool, len(ops))
	for i := range ops {
		failed[i] = true
	}
	return failed, err
}
