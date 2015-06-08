package securecouchbase

// Bucket an interface for go-couchbase bucket
type Bucket interface {
	Get(k string, rv interface{}) error
	Gets(k string, rv interface{}, caso *uint64) error
	Set(k string, exp int, v interface{}) error
	Add(k string, exp int, v interface{}) (bool, error)
	Delete(k string) error
	Cas(k string, exp int, cas uint64, v interface{}) error
	Incr(k string, amt, def uint64, exp int) (val uint64, err error)
}
