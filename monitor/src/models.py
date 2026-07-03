"""
DelegateGuard Monitor — core data models.
All monitor components share these dataclasses.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time


class DelegateStatus(str, Enum):
    UNKNOWN   = "unknown"
    SAFE      = "safe"       # audited / verified clean
    MALICIOUS = "malicious"  # confirmed sweeper / exploit
    SUSPICIOUS = "suspicious" # unverified, has risk signals
    REVOKED   = "revoked"    # delegation cleared (code slot zeroed)


class AlertLevel(str, Enum):
    INFO     = "INFO"
    WARNING  = "WARNING"
    CRITICAL = "CRITICAL"


# The EIP-7702 delegation designator prefix (23 bytes total: 3 prefix + 20 address)
DELEGATION_PREFIX = "0xef0100"


@dataclass
class DelegationEvent:
    """
    Represents a single EIP-7702 delegation observed on-chain.
    Parsed from a type-4 transaction's authorization list.
    """
    tx_hash:        str
    block_number:   int
    block_timestamp: int
    eoa_address:    str           # the EOA that delegated
    delegate_address: str         # the contract delegated TO
    chain_id:       int
    nonce:          int
    is_revocation:  bool = False  # True if delegate == address(0)

    def age_seconds(self) -> int:
        return int(time.time()) - self.block_timestamp

    def to_dict(self) -> dict:
        return {
            "tx_hash":          self.tx_hash,
            "block_number":     self.block_number,
            "block_timestamp":  self.block_timestamp,
            "eoa_address":      self.eoa_address,
            "delegate_address": self.delegate_address,
            "chain_id":         self.chain_id,
            "nonce":            self.nonce,
            "is_revocation":    self.is_revocation,
        }


@dataclass
class DelegateRecord:
    """
    Registry entry for a known delegate contract address.
    """
    address:        str
    status:         DelegateStatus
    name:           Optional[str]       = None   # human label e.g. "OZ DelegateA v1"
    notes:          Optional[str]       = None   # why it was classified
    risk_signals:   list[str]           = field(default_factory=list)
    first_seen_block: Optional[int]     = None
    eoa_count:      int                 = 0      # number of EOAs currently pointing here
    added_by:       str                 = "auto" # "auto" | "manual" | "community"

    def to_dict(self) -> dict:
        return {
            "address":        self.address,
            "status":         self.status.value,
            "name":           self.name,
            "notes":          self.notes,
            "risk_signals":   self.risk_signals,
            "first_seen_block": self.first_seen_block,
            "eoa_count":      self.eoa_count,
            "added_by":       self.added_by,
        }


@dataclass
class MonitorAlert:
    """
    Alert raised when a suspicious delegation is detected.
    """
    level:        AlertLevel
    title:        str
    message:      str
    eoa_address:  str
    delegate_address: str
    tx_hash:      str
    block_number: int
    timestamp:    int = field(default_factory=lambda: int(time.time()))
    risk_signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "level":            self.level.value,
            "title":            self.title,
            "message":          self.message,
            "eoa_address":      self.eoa_address,
            "delegate_address": self.delegate_address,
            "tx_hash":          self.tx_hash,
            "block_number":     self.block_number,
            "timestamp":        self.timestamp,
            "risk_signals":     self.risk_signals,
        }