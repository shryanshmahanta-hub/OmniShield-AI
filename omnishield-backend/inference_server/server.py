"""Mock/Reference inference server for Rook-1 ML classification model."""

from typing import Optional
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Rook-1 Inference Server", version="1.0.0")


class ClassificationRequest(BaseModel):
    text: str
    context: Optional[str] = None


class ClassificationResponse(BaseModel):
    model: str = "rook-1"
    label: str
    confidence: float


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "rook-inference-server"}


@app.post("/classify", response_model=ClassificationResponse)
def classify(request: ClassificationRequest) -> ClassificationResponse:
    lower_text = request.text.lower()
    if any(k in lower_text for k in ["ignore previous", "jailbreak", "dan", "evilbot"]):
        return ClassificationResponse(label="malicious_injection", confidence=0.96)
    if any(k in lower_text for k in ["urgent wire", "account suspended", "verify password"]):
        return ClassificationResponse(label="phishing_threat", confidence=0.91)
    return ClassificationResponse(label="benign", confidence=0.88)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
