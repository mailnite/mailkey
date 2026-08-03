# Proposal — how a publisher gets an EXTERNAL view of its own advertisement

Status: proposal, not specified. Addresses spec 07 §9, which requires a publisher
to compare four values but does not say how the outer two are obtained.

```text
configured   what this server is told to sign with    local
served       what its own handler returns             local
external     what the world's HTTPS fetch returns     ← needs a vantage point
DNS          what the world's resolvers see           ← needs a vantage point
```

## What actually goes wrong

Not exotic things. The failures that stop a correspondent fetching your manifest
are ordinary and mostly live BELOW the manifest:

- a port that is not open, or open on the wrong interface
- no TLS certificate for `mail.<d>`, or one that does not cover it, or expired
- a bind error at boot that left the listener down
- a proxy in front answering wrongly, or not at all
- routing, firewall, NAT — the ordinary weather of running a server

Every one of these produces the same symptom from the outside — no usable
manifest — and none of them is visible to a server asking itself. That is the
case to solve, not certificate mis-issuance.

## The vantage point already exists: the relay

Most installations run mailrelay, and several relays are plausible later. A relay
is a genuinely external observer by construction — its own network, its own
interface, its own public IP, and it is already the path the world's mail takes
to reach this server. It is also *ours*: no third party, no new trust
relationship, no telling anybody which domains we host.

So the proposal is to extend the relay protocol with two probe operations:

```text
relay.resolve   query DNS from the relay's network   (external UDP routing)
relay.fetch     GET https://mail.<d>/.well-known/mail-key from the relay
```

`relay.resolve` answers the DNS half from a resolver we do not run, past every
local cache and past split-horizon. `relay.fetch` answers the HTTPS half over the
real public path — which is precisely the path that a closed port, a missing
certificate or a dead listener breaks.

With more than one relay, the vantage points multiply and disagreement between
them is itself a finding.

**A relay is a probe, never an authority.** Its answer may raise a finding; it may
never move a key, change a manifest, edit DNS, or affect delivery.

### The standalone case is the hard one

A server with no relay and no outbound path to speak of cannot obtain an external
view at all, and no amount of design changes that. It should say so — "not
checked externally" — rather than run a local fetch and present the result as if
it meant something. An honest gap beats a comfortable answer, and it is the same
rule as everywhere else here: absence of evidence must not be displayed as
evidence.

## The correspondents' view is already in the envelope

An earlier draft of this proposal invented a `Mail-Key-Seen` header for peers to
report what they observed of us. That was wrong, and wrong in a way this project
has already been bitten by twice: a header is unauthenticated, strippable, and
detached from the thing it describes. A claim resting on one is C-01.

**The data is already where it is used.** The envelope header binds `Domain`,
`Kid` and `ManifestID` as AAD (envelope §"aad = canonical value.Pack of the
header map"). Every message a peer seals to us therefore names — authenticated,
unforgeable and unstrippable — exactly which manifest of ours that sender
fetched, from their network, at that moment. Nothing needs to be added, reported,
or trusted.

Two properties fall out, and the second is the one no probe can give:

**Ordinary agreement is free.** The AAD is readable before decryption (it has to
be, to select the key), so every inbound sealed message is an observation of what
one correspondent saw. Aggregate them and you have "what the world is using",
sampled by real mail, across every network that writes to you.

**Interception announces itself.** An attacker serving a forged manifest for our
domain makes our correspondents seal to a key we do not hold. Those messages
arrive and *cannot be opened* — and their AAD names a `ManifestID` we never
published. An undecryptable arrival naming an unknown manifest of ours is not an
error to log and move past; it is the interception detector, it cannot be forged,
and it costs nothing.

That failure is already visible in the delivery path (`InboundDecrypt` warns
today). What is missing is treating it as a SIGNAL about our own advertisement
rather than as one message's bad luck: compare the named `ManifestID` against our
publication history and sort it.

| AAD names | Meaning |
|---|---|
| our current manifest | agreement |
| an older manifest of ours | ordinary caching, bounded by its expiry |
| a manifest we NEVER published | someone is publishing forged manifests for us |

## Certificate Transparency, as a complement

Monitoring CT logs for `mail.<d>` catches the one case the two layers above
cannot: an interceptor holding a validly issued certificate serves a
*correct-looking* answer, so the relay's fetch succeeds and TLS validates. Only
the certificate's provenance is wrong, and that is recorded in an append-only log
nobody has to be trusted to operate.

Lower priority than the other two — it addresses the rarest failure.

## Coverage

| Failure | relay probes | envelope AAD | CT |
|---|---|---|---|
| port closed / wrong interface | ✓ | — | — |
| missing or wrong TLS certificate | ✓ | — | — |
| listener down after a bind error | ✓ | — | — |
| proxy answering wrongly | ✓ | ✓ | — |
| DNS never updated / split-horizon | ✓ | — | — |
| stale manifest still in use | — | ✓ | — |
| forged manifest served to peers | — | ✓ (undecryptable, unknown id) | ✓ |
| mis-issued certificate | — | ✓ | ✓ |

## Order of work

1. **Envelope-derived observation.** No protocol change at all — the identifiers
   are already bound and already arriving. Sort inbound `ManifestID`s against the
   publication history and surface the third row.
2. **Relay probes.** `relay.resolve` and `relay.fetch`, plus the multi-relay
   disagreement case. This is where the ordinary failures live.
3. **CT monitoring.** The rarest case, and the only one needing an outside feed.

## Open questions

- How long must publication history be retained for the three-way sort to stay
  accurate? Long enough to outlive the longest manifest lifetime plus a delivery
  window — the same shape as the key retention floor already computed elsewhere.
- Does a relay probe need its own timeout and failure semantics distinct from
  mail relaying, so a probe outage never looks like a relay outage?
- With several relays, is disagreement between them reported per relay, or as one
  finding? Per relay: "which vantage point sees what" is the diagnostic.
