/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package mailkey_test

import (
	"testing"
	"time"

	"github.com/mailnite/mailkey"
)

var t0 = time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)

/*
TestFirstOccurrenceIsReportedOnceIsTheWholePoint.

Spec 07 §12 P4 requires an operator to hear about a condition once per domain
per condition, not once per message. A domain that holds four hundred messages
overnight is one problem, and four hundred notifications is how an operator
learns to dismiss the whole category without reading it.
*/
func TestFirstOccurrenceIsReportedOnceIsTheWholePoint(t *testing.T) {
	var issues []mailkey.PeerIssue
	firsts := 0
	for i := 0; i < 400; i++ {
		var first bool
		issues, first = mailkey.CoalesceIssue(issues, mailkey.IssueMailHeld, "no key", t0.Add(time.Duration(i)*time.Minute))
		if first {
			firsts++
		}
	}
	if firsts != 1 {
		t.Fatalf("400 held messages produced %d alerts; an operator would learn to ignore the category", firsts)
	}
	if len(issues) != 1 || issues[0].Count != 400 {
		t.Fatalf("occurrences did not coalesce: %+v", issues)
	}
	if !issues[0].FirstSeen.Equal(t0) {
		t.Fatalf("first-seen moved to %v — the history lost when this started", issues[0].FirstSeen)
	}
	if !issues[0].LastSeen.Equal(t0.Add(399 * time.Minute)) {
		t.Fatalf("last-seen is %v — the history cannot say whether this is still happening", issues[0].LastSeen)
	}
}

// TestRecurrenceAfterAClearIsNews: a condition that stops and comes back is a
// new fact, not a footnote on a months-old row.
func TestRecurrenceAfterAClearIsNews(t *testing.T) {
	issues, _ := mailkey.CoalesceIssue(nil, mailkey.IssueSignerChanged, "a", t0)
	issues = mailkey.ClearIssue(issues, mailkey.IssueSignerChanged)
	if len(issues) != 0 {
		t.Fatalf("clear left %+v", issues)
	}
	_, first := mailkey.CoalesceIssue(issues, mailkey.IssueSignerChanged, "b", t0.Add(time.Hour))
	if !first {
		t.Fatal("a condition that recurred after clearing was reported as already known")
	}
}

// TestClearOnlyTouchesItsOwnCondition: resolving one problem must not silence
// the others, or a peer that fixes its proof stops reporting its held mail.
func TestClearOnlyTouchesItsOwnCondition(t *testing.T) {
	issues, _ := mailkey.CoalesceIssue(nil, mailkey.IssueProofMissing, "", t0)
	issues, _ = mailkey.CoalesceIssue(issues, mailkey.IssueMailHeld, "", t0)
	issues = mailkey.ClearIssue(issues, mailkey.IssueProofMissing)
	if len(issues) != 1 || issues[0].Code != mailkey.IssueMailHeld {
		t.Fatalf("clearing one condition disturbed the others: %+v", issues)
	}
}

/*
TestTheCapEvictsTheStALEST: with more conditions than the bound, the row that
goes is the one that stopped happening — not the one that started earliest.

A condition that began months ago and still fires every hour is the live
problem. Evicting by first-seen would drop exactly that in favour of something
that happened once and never again.
*/
func TestTheCapEvictsTheStalest(t *testing.T) {
	codes := []mailkey.IssueCode{
		mailkey.IssueSignerChanged, mailkey.IssueProofMissing, mailkey.IssuePinWithheld,
		mailkey.IssueReplay, mailkey.IssueAuthorityUnstable, mailkey.IssueDowngradeBlocked,
		mailkey.IssueMailHeld, mailkey.IssueRefreshFailed,
	}
	var issues []mailkey.PeerIssue
	// The oldest-started condition, still firing.
	issues, _ = mailkey.CoalesceIssue(issues, codes[0], "", t0)
	for i, c := range codes[1:] {
		issues, _ = mailkey.CoalesceIssue(issues, c, "", t0.Add(time.Duration(i+1)*time.Hour))
	}
	// It fires again, most recently of all.
	issues, _ = mailkey.CoalesceIssue(issues, codes[0], "", t0.Add(99*time.Hour))
	if len(issues) != mailkey.MaxPeerIssues {
		t.Fatalf("expected the list full at %d, got %d", mailkey.MaxPeerIssues, len(issues))
	}
	// One more distinct condition forces an eviction.
	issues, _ = mailkey.CoalesceIssue(issues, mailkey.IssueCode("something-new"), "", t0.Add(100*time.Hour))
	if len(issues) != mailkey.MaxPeerIssues {
		t.Fatalf("the history is unbounded: %d rows", len(issues))
	}
	has := func(c mailkey.IssueCode) bool {
		for _, x := range issues {
			if x.Code == c {
				return true
			}
		}
		return false
	}
	// codes[1] last fired at t0+1h and never again: it is the stalest, so it is
	// what goes.
	if has(codes[1]) {
		t.Fatalf("the stalest condition survived eviction: %+v", issues)
	}
	// codes[0] started first and fired most recently. Evicting by first-seen
	// would drop exactly this — the live problem — and keep something that
	// happened once.
	if !has(codes[0]) {
		t.Fatalf("the live, oldest-started condition was evicted: %+v", issues)
	}
}

/*
TestOnlyActionableConditionsAlert.

The line is ACTIONABILITY, not severity. A refresh failure is often worse for
the sender than a withheld pin and is still not alerted: there is nothing an
operator can do about someone else's outage, and an alert that fires routinely
is one that gets ignored — which is the same reasoning §7 uses to restrict what
DNS may carry.
*/
func TestOnlyActionableConditionsAlert(t *testing.T) {
	for _, c := range []mailkey.IssueCode{
		mailkey.IssueSignerChanged, mailkey.IssuePinWithheld,
		mailkey.IssueDowngradeBlocked, mailkey.IssueMailHeld,
		// Only ever raised for an already-PINNED domain, so it is never the
		// routine case: the operator pinned it to hear exactly this.
		mailkey.IssueProofMissing, mailkey.IssueForeignSeal, mailkey.IssueRevoked,
	} {
		if !c.Alerts() {
			t.Errorf("%s is worth waking someone for and does not alert", c)
		}
	}
	for _, c := range []mailkey.IssueCode{
		mailkey.IssueRefreshFailed, mailkey.IssueReplay, mailkey.IssueCode(""),
		// AuthorityUnstable has its OWN notification where the instability is
		// detected; alerting twice for one condition is how a category gets muted.
		mailkey.IssueAuthorityUnstable,
	} {
		if c.Alerts() {
			t.Errorf("%s alerts; routine conditions teach operators to dismiss the category", c)
		}
	}
}

// TestCoalesceDoesNotMutateItsInput: the store reads a peer, folds an issue and
// writes it back — aliasing the caller's slice would make a CAS retry replay
// the previous attempt's mutation on top of freshly read state.
func TestCoalesceDoesNotMutateItsInput(t *testing.T) {
	orig, _ := mailkey.CoalesceIssue(nil, mailkey.IssueMailHeld, "one", t0)
	snapshot := orig[0]
	if _, _ = mailkey.CoalesceIssue(orig, mailkey.IssueMailHeld, "two", t0.Add(time.Hour)); orig[0] != snapshot {
		t.Fatalf("the input slice was mutated: %+v became %+v", snapshot, orig[0])
	}
}
