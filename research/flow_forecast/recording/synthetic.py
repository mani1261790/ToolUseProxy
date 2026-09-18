"""Fresh, sealed artificial inputs for exercising the record-only worker.

This is an experiment source, not a live ToolCall adapter. Workspace identities
are namespaced to the dataset location; request data never proves freshness.
"""
from dataclasses import asdict
from pathlib import Path

from hook_monitor.evaluation.flow_forecast.dataset import read_dataset
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError, digest
from .contracts import Binding, Current, Request, RecordingSourceError
from ..artifacts import load_model


class SyntheticSource:
    def __init__(self, directory: Path, model: Path, journal):
        self.directory = directory
        self.model = model
        self.journal = journal
        self.workspace = 'synthetic.' + digest(str(directory.resolve()))

    def observation(self, candidate_id, policy_mode, horizon):
        generation = self.journal.configured(self.workspace)
        if generation is None:
            raise ForecastDataError('unconfigured_recording_experiment')
        try:
            dataset = read_dataset(self.directory)
        except (ForecastDataError, OSError):
            raise RecordingSourceError('input_unavailable') from None
        prefix = next((p for p in dataset.prefixes if p.prefix_id == candidate_id), None)
        if prefix is None:
            raise RecordingSourceError('input_version_changed')
        binding = Binding(
            self.workspace, prefix.root_case_id, 'observation-' + str(prefix.max_sequence_no),
            prefix.prefix_id, digest(prefix.model_input()),
            digest([prefix.source_version, prefix.protected_sources]),
            digest([prefix.environment_version, policy_mode, horizon]),
            prefix.snapshot_digest, prefix.max_sequence_no, generation,
        )
        return prefix, binding

    def model_digest(self):
        if not self.model.exists():
            raise RecordingSourceError('model_missing')
        try:
            return load_model(self.model).model_digest
        except (ForecastDataError, OSError):
            raise RecordingSourceError('model_invalid') from None

    def request(self, candidate_id, *, now, policy_mode='observe', horizon=4):
        prefix, binding = self.observation(candidate_id, policy_mode, horizon)
        return Request(binding, prefix, self.model_digest(), now,
                       policy_mode=policy_mode, horizon=horizon)

    def current(self, request):
        if request.input_scope != 'synthetic' or request.binding.workspace_id != self.workspace:
            raise ForecastDataError('recording_source_mismatch')
        prefix, binding = self.observation(request.binding.candidate_id, request.policy_mode, request.horizon)
        # Prefix is reloaded from the sealed artifact, not reconstructed from the
        # request. Targets in the dataset are never supplied to the predictor.
        if asdict(prefix) != asdict(request.prefix):
            raise ForecastDataError('recording_prefix_changed')
        return Current(binding, self.model_digest())
