package securecouchbase

import gocb "gopkg.in/couchbase/gocb.v1"

// Bucket an interface for go-couchbase bucket
type Bucket interface {
	Get(k string, rv interface{}) (gocb.Cas, error)
	Counter(key string, delta, initial int64, expiry uint32) (uint64, gocb.Cas, error)
	Upsert(string, interface{}, uint32) (gocb.Cas, error)
	// Add(k string, exp int, v interface{}) (bool, error)
	SetAdd(key string, value interface{}, createSet bool) (gocb.Cas, error)
	Remove(key string, cas gocb.Cas) (gocb.Cas, error)
}
