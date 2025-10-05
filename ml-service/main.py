from fastapi import FastAPI, Request
from pydantic import BaseModel
from transformers import pipeline
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Enable CORS for local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load a pre-trained zero-shot classification model
classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

class ScanRequest(BaseModel):
    text: str
    labels: list[str]

@app.post("/scan")
async def scan_text(request: ScanRequest):
    result = classifier(request.text, request.labels)
    return {
        "text": request.text,
        "labels": result["labels"],
        "scores": result["scores"]
    }
