"""
Re-export Finding model from analyzer.core.finding.
Scanner detectors use the same Finding dataclass as the analyzer.
"""
from analyzer.core.finding import Finding, Severity, BugClass  # noqa: F401

__all__ = ["Finding", "Severity", "BugClass"]