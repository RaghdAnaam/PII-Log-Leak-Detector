from abc import ABC, abstractmethod
from backend.app.models.findings import Finding


class PIIDetector(ABC):
    @abstractmethod
    def detect(self, text: str, file: str = "", line_offset: int = 1) -> list[Finding]:
        """Scan `text` for potential PII. Returns findings with accurate line numbers."""
        ...
