# pyright: reportMissingModuleSource=false
import gdb
from typing import Dict, List
from collections import defaultdict


class GenericSession:
    """
    Info: Container for storing information during a debugging session.
    """
    # past usages of heap slots
    slot_histories: Dict[int, List[str]] = defaultdict(list)

    def __init__(self) -> None:
        pass


