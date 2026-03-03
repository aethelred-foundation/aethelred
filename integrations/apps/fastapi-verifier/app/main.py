from __future__ import annotations

import os
from typing import Any, Dict, List

from fastapi import FastAPI
from pydantic import BaseModel, Field

from aethelred.integrations import (
    AethelredVerificationMiddleware,
    VerificationEnvelope,
    VerificationRecorder,
    wrap_langchain_runnable,
    wrap_pytorch_model,
    wrap_transformers_pipeline,
)


APP_NAME = "aethelred-fastapi-verifier"
VERIFY_MODE = os.getenv("AETHELRED_VERIFY_MODE", "seal-envelope")
RPC_URL = os.getenv("AETHELRED_RPC_URL", "http://localhost:26657")
HEADER_PREFIX = os.getenv("AETHELRED_HEADER_PREFIX", "x-aethelred")

app = FastAPI(title="Aethelred FastAPI Verifier", version="0.1.0")

_recent_envelopes: List[Dict[str, Any]] = []


def _record_sink(envelope: VerificationEnvelope) -> None:
    _recent_envelopes.append(
        {
            "trace_id": envelope.trace_id,
            "framework": envelope.framework,
            "operation": envelope.operation,
            "input_hash": envelope.input_hash,
            "output_hash": envelope.output_hash,
            "timestamp_ms": envelope.timestamp_ms,
            "metadata": envelope.metadata,
        }
    )
    # Bound in-memory history for demo safety.
    if len(_recent_envelopes) > 200:
        del _recent_envelopes[: len(_recent_envelopes) - 200]


recorder = VerificationRecorder(
    sink=_record_sink,
    default_metadata={"service": APP_NAME, "rpc_url": RPC_URL, "verify_mode": VERIFY_MODE},
    header_prefix=HEADER_PREFIX,
)

app.add_middleware(
    AethelredVerificationMiddleware,
    recorder=recorder,
    exclude_paths=["/health", "/metrics"],
    header_prefix=HEADER_PREFIX,
)


class FraudRequest(BaseModel):
    features: List[float] = Field(default_factory=list)
    threshold: float = 0.5


class FraudResponse(BaseModel):
    score: float
    flagged: bool
    explanation: str


class PromptRequest(BaseModel):
    text: str


class _FraudModel:
    def __call__(self, features: List[float], threshold: float = 0.5) -> Dict[str, Any]:
        score = sum(features) / max(len(features), 1)
        return {
            "score": round(score, 6),
            "flagged": score >= threshold,
            "explanation": "demo-linear-risk-score",
        }


class _TransformerStub:
    task = "text-classification"

    def __call__(self, text: str) -> List[Dict[str, Any]]:
        risk_terms = ("suspend", "wire", "urgent", "override", "password")
        score = 0.99 if any(t in text.lower() for t in risk_terms) else 0.08
        label = "RISK" if score > 0.8 else "SAFE"
        return [{"label": label, "score": score, "text": text}]


class _LangChainStub:
    def invoke(self, payload: Dict[str, Any], config: Any = None) -> Dict[str, Any]:
        text = str(payload.get("input", ""))
        return {
            "answer": text.upper(),
            "strategy": "demo-rule-chain",
            "config": config,
        }


verified_fraud_model = wrap_pytorch_model(_FraudModel(), recorder=recorder, component_name="FraudModelDemo")
verified_transformer = wrap_transformers_pipeline(
    _TransformerStub(),
    recorder=recorder,
    component_name="TextRiskPipeline",
)
verified_chain = wrap_langchain_runnable(
    _LangChainStub(),
    recorder=recorder,
    component_name="NormalizerChain",
)


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": APP_NAME,
        "verify_mode": VERIFY_MODE,
        "rpc_url": RPC_URL,
    }


@app.post("/infer/fraud", response_model=FraudResponse)
def infer_fraud(payload: FraudRequest) -> Dict[str, Any]:
    return verified_fraud_model(payload.features, threshold=payload.threshold)


@app.post("/infer/text-risk")
def infer_text_risk(payload: PromptRequest) -> Dict[str, Any]:
    result = verified_transformer(payload.text)
    return {"result": result}


@app.post("/chain/normalize")
def chain_normalize(payload: PromptRequest) -> Dict[str, Any]:
    return verified_chain.invoke({"input": payload.text}, config={"tenant": "demo"})


@app.get("/verify/recent")
def recent_verifications(limit: int = 20) -> Dict[str, Any]:
    limit = max(1, min(limit, 100))
    return {"items": _recent_envelopes[-limit:][::-1]}
