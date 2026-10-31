package mva

import "encoding/gob"

func init() {
	gob.Register(attrKey{})
	gob.Register(idKey{})
	gob.Register(AttrRangeQuery{})
	gob.Register(LogIDQuery{})
	gob.Register(LogIDBatchQuery{})
	gob.Register(SiteQuery{})
	gob.Register(SiteDeviceQuery{})
	gob.Register(TimeRangeQuery{})
}
