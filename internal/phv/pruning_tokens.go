package phv

import (
	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

// HPBF's three-slot API checks all slots. Repeating the deepest available
// prefix preserves Site and Site+Device query semantics without a new filter.
func pruningTokens(query mva.LocatorQuery) ([3][]byte, bool, error) {
	var tokens [3][]byte
	var site, device, kind string
	switch q := query.(type) {
	case mva.SiteQuery:
		site = q.SiteID
	case mva.SiteDeviceQuery:
		site, device = q.SiteID, q.DevID
	case mva.AttrRangeQuery:
		site, device, kind = q.SiteID, q.DevID, q.Type
	default:
		return tokens, false, nil
	}
	if site == "" || (kind != "" && device == "") {
		return tokens, false, nil
	}
	var err error
	if tokens[0], err = domain.Serialize(site); err != nil {
		return tokens, false, err
	}
	tokens[1], tokens[2] = tokens[0], tokens[0]
	if device != "" {
		if tokens[1], err = domain.Serialize(site, device); err != nil {
			return tokens, false, err
		}
		tokens[2] = tokens[1]
	}
	if kind != "" {
		if tokens[2], err = domain.Serialize(site, device, kind); err != nil {
			return tokens, false, err
		}
	}
	return tokens, true, nil
}
