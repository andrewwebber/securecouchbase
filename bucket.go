package securecouchbase

// Bucket an interface for go-couchbase bucket
type Bucket interface {
	Get(k string, rv interface{}) error
	Set(k string, exp int, v interface{}) error
	Delete(k string) error
	Incr(k string, amt, def uint64, exp int) (val uint64, err error)
}
