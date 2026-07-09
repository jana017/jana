"""Pydantic models for the CyberLab platform."""
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class RecipeStep(BaseModel):
    """A single step in a decoding/analysis recipe."""
    id: str = Field(..., description="Plugin ID, e.g. 'base64-decode'")
    params: Dict[str, Any] = Field(default_factory=dict)
    disabled: bool = False


class RunRecipeRequest(BaseModel):
    """Request to execute a manual recipe pipeline."""
    input: str = Field(..., description="Raw input payload (text)")
    recipe: List[RecipeStep] = Field(default_factory=list)
    encoding: str = Field(default="utf-8", description="Input text encoding hint")


class AutoDecodeRequest(BaseModel):
    """Request to auto-decode a payload with confidence scoring."""
    input: str
    max_depth: int = Field(default=8, ge=1, le=20)
    include_analysis: bool = True


class AnalyzeRequest(BaseModel):
    """Request to run full threat analysis on a payload."""
    input: str
    auto_decode: bool = True


class StepResult(BaseModel):
    """Result of a single pipeline step."""
    id: str
    name: str
    category: str
    input_preview: str
    output_preview: str
    output_size: int
    duration_ms: float
    confidence: Optional[float] = None
    error: Optional[str] = None
    meta: Dict[str, Any] = Field(default_factory=dict)


class Ioc(BaseModel):
    """Extracted indicator of compromise."""
    type: str  # ipv4, ipv6, domain, url, email, md5, sha1, sha256, sha512, btc, mac, cve, filepath, registry
    value: str
    context: str = ""


class MitreTechnique(BaseModel):
    """A MITRE ATT&CK technique match."""
    id: str  # e.g. T1059.001
    name: str
    tactic: str
    description: str
    evidence: List[str] = Field(default_factory=list)


class YaraLikeMatch(BaseModel):
    """A pattern rule match."""
    rule: str
    tags: List[str] = Field(default_factory=list)
    severity: str = "medium"  # info, low, medium, high, critical
    description: str = ""
    matched: List[str] = Field(default_factory=list)


class RiskReason(BaseModel):
    """A structured indicator explaining part of the computed risk score."""
    label: str
    severity: str = "medium"  # high | medium | low
    category: str = "forensic"  # encoding, execution, lolbin, network, persistence, impact, credential, recon, forensic
    evidence: str = ""


class AnalysisReport(BaseModel):
    """Full analysis report."""
    input_size: int
    final_output: str
    trace: List[StepResult] = Field(default_factory=list)
    iocs: List[Ioc] = Field(default_factory=list)
    mitre: List[MitreTechnique] = Field(default_factory=list)
    rules: List[YaraLikeMatch] = Field(default_factory=list)
    risk_score: int = 0  # 0-100
    verdict: str = "clean"  # clean, suspicious, malicious
    summary: str = ""
    risk_reasons: List[RiskReason] = Field(default_factory=list)
    duration_ms: float = 0.0


class PluginInfo(BaseModel):
    id: str
    name: str
    category: str
    description: str
    params: List[Dict[str, Any]] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
