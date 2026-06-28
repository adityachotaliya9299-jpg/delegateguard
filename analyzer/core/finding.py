"""
DelegateGuard — core finding model.
Every detector returns a list of Finding objects.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    INFO     = "INFO"


class BugClass(str, Enum):
    # Delegate-contract bugs (E1)
    DC01_STORAGE_COLLISION    = "DC-01"
    DC02_INIT_FRONTRUN        = "DC-02"
    DC03_CROSS_CHAIN_REPLAY   = "DC-03"
    DC04_MISSING_AUTH         = "DC-04"
    DC05_INNER_DELEGATECALL   = "DC-05"
    DC06_BATCH_REPLAY         = "DC-06"
    DC07_SWEEPER              = "DC-07"
    DC08_SIG_MALLEABILITY     = "DC-08"
    # Protocol-assumption bugs (E2)

    PA01_TX_ORIGIN            = "PA-01"
    PA02_SENDER_ORIGIN_GATE   = "PA-02"
    PA03_EXTCODESIZE          = "PA-03"
    PA04_EOA_REENTRANCY       = "PA-04"
    PA05_EOA_UNIQUENESS       = "PA-05"


@dataclass
class Finding:
    bug_class:   BugClass
    severity:    Severity
    title:       str
    description: str
    contract:    str
    function:    Optional[str] = None
    line:        Optional[int] = None
    source_file: Optional[str] = None
    recommendation: str = ""
    poc_ref:     str = ""          # path to PoC in lab/

    def to_dict(self) -> dict:
        return {
            "bug_class":      self.bug_class.value,
            "severity":       self.severity.value,
            "title":          self.title,
            "description":    self.description,
            "contract":       self.contract,
            "function":       self.function,
            "line":           self.line,
            "source_file":    self.source_file,
            "recommendation": self.recommendation,
            "poc_ref":        self.poc_ref,
        }