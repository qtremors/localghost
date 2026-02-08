"""Summarize attempted probes without turning missing evidence into a pass."""

from dataclasses import dataclass


@dataclass
class ProbeCoverage:
    attempted: int = 0
    completed: int = 0

    def record(self, completed: bool):
        self.attempted += 1
        self.completed += int(completed)

    def merge(self, attempted: int, completed: int):
        self.attempted += attempted
        self.completed += min(attempted, max(0, completed))

    @property
    def inconclusive(self):
        return self.attempted - self.completed

    @property
    def status(self):
        if not self.completed:
            return 'error'
        return 'partial' if self.inconclusive else 'success'

    def to_dict(self):
        return {'attempted': self.attempted, 'completed': self.completed, 'inconclusive': self.inconclusive}
