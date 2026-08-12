# Network egress synthetic corpus v1

This fixture contains labels only. It intentionally stores no command, argv,
hostname, URL, DNS label, credential, payload, protected value, or file content.

The recorded observations are synthetic. Running the evaluator never executes a
target program or opens a network connection. `development` and `validation`
both include public and protected payload classes, external attempts, local
negative controls, and surfaces that a local process observer cannot measure.

`protected` is only a class label. It is not a protected value and is not used to
infer leakage by this externality benchmark.
