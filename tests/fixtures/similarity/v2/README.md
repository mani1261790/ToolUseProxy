# similarity/v2 fixture contract

`v2` is the production-equivalent similarity evaluation corpus. It keeps the
immutable `v1` files as historical evidence and adds a separately registered
schema with exact split baselines.

The corpus is synthetic and contains no real credentials. Development and
validation use disjoint pair, candidate, and scenario families. The loader also
pins aggregate vocabulary/feature overlap, distinct structural shape digests,
and the absence of one non-stop marker shared by every scored text. These checks
prevent a regenerated validation split from becoming a renamed mirror of
development or from gaining an artificial shared prefix.

Each split contains:

- scored positive and negative pairs, plus one semantic-paraphrase case that is
  visible in `all` metrics but excluded from the GO gate;
- typed counterfactual pairs at pair, candidate, and end-to-end layers;
- four artifact pools of 53 candidates and four source pools of 203 candidates;
- candidate pressure where long, pair-rejected decoys outrank a true short
  containment, without relying on an exact-key shortcut;
- artifact cap counterfactuals where 49 versus 50 five-character, pair-ineligible
  decoys put an eligible plural-alias candidate at legacy rank 50 versus 51;
- source cap counterfactuals where 199 versus 201 identical five-character,
  low-signal decoys put an eligible token-alias candidate at legacy coverage
  rank 200 versus 202 while it remains first by raw overlap;
- long alpha-only secret containment paired against exact-only common labels,
  with a production source-to-sink scenario in the development split;
- external-sink scenarios with reachability and policy-action labels.

Large deterministic inputs are stored as bounded expansion recipes. Saturated
candidate pools use deterministic series recipes with one explicitly labeled
relevant text. A bounded constant-decoy recipe represents repeated low-signal
pressure without duplicating 201 candidate bodies in the fixture. The loader
expands all forms in memory and caps expansion size.
Lexical ranking excludes normalized candidates shorter than eight characters
for artifact flow and four for source binding. It then takes equal quotas from
coverage-first and overlap-first deterministic orderings and backfills from the
coverage ordering. The source three/four boundary is covered by an evaluator
adapter unit because a three-character value cannot naturally overlap a longer
query under the five-character shingle profile.
The committed fixture digest covers the recipes, labels, thresholds, family
contract, and exact development/validation/all outcome baselines.

Reports may contain stable case IDs and aggregate digests, but never fixture
bodies or the SHA-256 of an individual fixture body. `--check` verifies corpus,
baseline, privacy, cap, and full/incremental invariants. `--require-go` is the
separate promotion decision. The fixed v2 baseline requires both commands to
pass for development, validation, and all.
