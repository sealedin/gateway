// Package limits holds the numbers two services must agree on; stdlib only, so the drain can link it.
package limits

import "time"

const (
	// UpstreamCall is how long the egress holds one upstream call, streaming included.
	UpstreamCall = 10 * time.Minute
	// ParallelRequests is how many requests one key may have running. A judgment, not a measurement: room for an agent's
	// subagents, and a bound on what one key has running upstream.
	ParallelRequests = 10
)
