from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.engine import maybe_generate_with_llm


class GenerateRequest(BaseModel):
    vendor_name: str = Field(min_length=1, max_length=200)
    vendor_type: str = Field(min_length=1, max_length=100)
    evidence_text: str = Field(min_length=1)


app = FastAPI(title="Brisk API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/generate")
def generate(request: GenerateRequest) -> dict:
    return maybe_generate_with_llm(
        vendor_name=request.vendor_name,
        vendor_type=request.vendor_type,
        evidence_text=request.evidence_text,
    )
