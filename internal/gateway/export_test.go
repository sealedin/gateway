package gateway

// ValidatePricingAgainst lets tests inject a synthetic price sheet; production callers get only the bound one.
func (m ModelList) ValidatePricingAgainst(prices map[string]Price) error {
	return m.validatePricing(prices)
}

// AddressSet exposes the placeholder check, now that the measured treasury is set.
var AddressSet = addressSet //nolint:gochecknoglobals // test export
