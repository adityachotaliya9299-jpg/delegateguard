"""
DelegateGuard detector registry — DC-01 through DC-08 only.
"""
from .dc01_storage_collision  import DC01_StorageCollisionDetector
from .dc02_init_frontrun      import DC02_InitFrontrunDetector
from .dc03_cross_chain_replay import DC03_CrossChainReplayDetector
from .dc04_missing_auth       import DC04_MissingAuthDetector
from .dc05_inner_delegatecall import DC05_InnerDelegatecallDetector
from .dc06_batch_replay       import DC06_BatchReplayDetector
from .dc07_sweeper            import DC07_SweeperDetector
from .dc08_sig_malleability   import DC08_SigMalleabilityDetector

DELEGATE_DETECTORS = [
    DC07_SweeperDetector,
    DC05_InnerDelegatecallDetector,
    DC03_CrossChainReplayDetector,
    DC01_StorageCollisionDetector,
    DC02_InitFrontrunDetector,
    DC04_MissingAuthDetector,
    DC06_BatchReplayDetector,
    DC08_SigMalleabilityDetector,
]

__all__ = [
    "DELEGATE_DETECTORS",
    "DC01_StorageCollisionDetector",
    "DC02_InitFrontrunDetector",
    "DC03_CrossChainReplayDetector",
    "DC04_MissingAuthDetector",
    "DC05_InnerDelegatecallDetector",
    "DC06_BatchReplayDetector",
    "DC07_SweeperDetector",
    "DC08_SigMalleabilityDetector",
]