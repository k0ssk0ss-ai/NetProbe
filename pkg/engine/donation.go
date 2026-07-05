package engine

import (
	"context"
	"sync"
	"time"
)

// donationScanTimeout bounds a single domain's scan inside a donation run.
const donationScanTimeout = 6 * time.Second

// RunDonation scans several domains in parallel and returns the anonymized results — the
// payload for a user-initiated "donate a test". It sends NOTHING: the client shows the
// preview and only uploads on explicit confirmation (privacy-first, see ROADMAP.md §8).
//
// Domains run concurrently, so the whole batch costs about one domain's scan (~a few
// seconds) instead of the sequential sum.
func RunDonation(ctx context.Context, domains []string) []AnonReport {
	results := make([]AnonReport, len(domains))
	var wg sync.WaitGroup
	for i, d := range domains {
		wg.Add(1)
		go func(idx int, domain string) {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, donationScanTimeout)
			defer cancel()
			results[idx] = Anonymize(RunEngineScans(dctx, domain))
		}(i, d)
	}
	wg.Wait()
	return results
}
