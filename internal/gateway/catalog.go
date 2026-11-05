package gateway

import (
	"slices"
	"strings"
)

// Provider and Tier name what every catalog model is: a Chutes GPU TEE instance behind the attested egress.
const (
	Provider = "chutes"
	Tier     = "gpu-tee"
)

// CatalogModel is one priced model of the signed catalog.
type CatalogModel struct {
	ID               string `json:"id"` // the gateway model id a client requests
	InputUSDPerMTok  string `json:"input_usd_per_mtok"`
	OutputUSDPerMTok string `json:"output_usd_per_mtok"`
	Provider         string `json:"provider"`
	Tier             string `json:"tier"`
	UpstreamID       string `json:"upstream_id"`
}

// Catalog is the measured price sheet with its provenance, the content the identity signs.
type Catalog struct {
	ListAsOf      string         `json:"list_as_of"`
	ListSource    string         `json:"list_source"`
	MarkupPercent uint           `json:"markup_percent"`
	Models        []CatalogModel `json:"models"`
	PayTo         string         `json:"pay_to"`   // the treasury a purchase pays
	Networks      []string       `json:"networks"` // CAIP-2 ids a purchase can settle on
	Asset         string         `json:"asset"`    // the mint a purchase pays in
}

// MeasuredCatalog is the price sheet with the measured payment terms.
func MeasuredCatalog() Catalog { return CatalogFor(MeasuredTerms()) }

// CatalogFor is every model of CanonicalModelPrices() under its served id, sorted by id; only the terms vary, and only
// on the unattested branch.
func CatalogFor(terms Terms) Catalog {
	prices := CanonicalModelPrices()
	models := make([]CatalogModel, 0, len(prices))
	for upstream, price := range prices {
		in, out := price.USDPerMTok()
		models = append(models, CatalogModel{ID: ServedModel(upstream), InputUSDPerMTok: in, OutputUSDPerMTok: out,
			Provider: Provider, Tier: Tier, UpstreamID: upstream})
	}
	slices.SortFunc(models, func(a, b CatalogModel) int { return strings.Compare(a.ID, b.ID) })
	return Catalog{ListAsOf: ListAsOf, ListSource: ListSource, MarkupPercent: MarkupPercent, Models: models,
		PayTo: terms.Treasury, Networks: []string{terms.Network}, Asset: terms.Asset}
}
