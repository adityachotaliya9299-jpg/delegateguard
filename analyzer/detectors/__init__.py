"""
DelegateGuard scanner detector registry.
"""
from .pa01_tx_origin         import PA01_TxOriginDetector
from .pa02_sender_origin_gate import PA02_SenderOriginGateDetector
from .pa03_extcodesize       import PA03_ExtcodesizeDetector
from .pa04_eoa_reentrancy    import PA04_EOAReentrancyDetector
from .pa05_eoa_uniqueness    import PA05_EOAUniquenessDetector

# Ordered by severity
SCANNER_DETECTORS = [
    PA04_EOAReentrancyDetector,    # CRITICAL
    PA01_TxOriginDetector,         # HIGH
    PA02_SenderOriginGateDetector, # HIGH
    PA03_ExtcodesizeDetector,      # HIGH
    PA05_EOAUniquenessDetector,    # MEDIUM
]

__all__ = [
    "SCANNER_DETECTORS",
    "PA01_TxOriginDetector",
    "PA02_SenderOriginGateDetector",
    "PA03_ExtcodesizeDetector",
    "PA04_EOAReentrancyDetector",
    "PA05_EOAUniquenessDetector",
]