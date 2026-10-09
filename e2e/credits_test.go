//go:build e2e && e2e_credits

package e2e

import (
	"testing"

	"github.com/nlink-jp/shodan-lookup/internal/engine"
)

// SPENDS ONE QUERY CREDIT. Run only through `make e2e-credits`, which says so
// first. One filtered search, refreshed so that no cached page answers it;
// the guard's own before/after read must show exactly the predicted credit.
//
// TestMain then requires the run to have spent exactly that one credit.
func init() { allowedSpend = 1 }

func TestCreditsAFilteredSearchSpendsWhatWasPredicted(t *testing.T) {
	s, err := eng.SearchServices(ctx(t), engine.SearchQuery{Query: "product:nginx country:JP"}, true)
	if err != nil {
		t.Fatalf("SearchServices: %v", err)
	}
	c := s.Credits
	if c == nil || c.Predicted != 1 || c.Spent == nil || *c.Spent != 1 {
		t.Errorf("credits: %+v — AGENTS.md says a filtered page 1 costs exactly 1", c)
	}
}
