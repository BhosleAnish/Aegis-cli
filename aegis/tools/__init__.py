"""Tool adapters: each wraps a free/OSS external binary and normalizes its output."""

from .base import Adapter, ToolResult, ToolStatus
from .nmap_adapter import NmapAdapter
from .nuclei_adapter import NucleiAdapter
from .httpx_adapter import HttpxAdapter
from .katana_adapter import KatanaAdapter
from .gau_adapter import GauAdapter
from .ffuf_adapter import FfufAdapter
from .dalfox_adapter import DalfoxAdapter

__all__ = [
    "Adapter",
    "ToolResult",
    "ToolStatus",
    "NmapAdapter",
    "NucleiAdapter",
    "HttpxAdapter",
    "KatanaAdapter",
    "GauAdapter",
    "FfufAdapter",
    "DalfoxAdapter",
]
