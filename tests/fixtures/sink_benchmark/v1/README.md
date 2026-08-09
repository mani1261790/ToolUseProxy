# Sink benchmark v1

This dataset compares sink-time detection profiles without changing production
policy. All values and prose are synthetic.

- `cases.jsonl` contains only ground truth and public taxonomy.
- `ingestion/` uses the existing source-ingestion v3 contract.
- development and validation use different synthetic vocabulary.
- paraphrase and file-reference cases intentionally expose current research gaps.
- reports must not include fixture bodies, protected values, value hashes, raw
  commands, or absolute workspace paths.
