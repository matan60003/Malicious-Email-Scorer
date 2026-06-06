from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any

class VTStats(BaseModel):
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    timeout: int = 0

class VTResult(BaseModel):
    stats: Optional[VTStats] = None
    error: Optional[str] = None

class SBResult(BaseModel):
    matches: List[Dict[str, Any]] = Field(default_factory=list)
    error: Optional[str] = None

class IntelResult(BaseModel):
    virustotal: Dict[str, VTResult] = Field(default_factory=dict)
    safebrowsing: SBResult = Field(default_factory=SBResult)
