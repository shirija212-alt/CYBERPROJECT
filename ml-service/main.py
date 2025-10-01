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

# Load a pre-trained spam detection model (sentiment analysis for now)
classifier = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")

class ScanRequest(BaseModel):
    text: str

@app.post("/scan/sms")
async def scan_sms(request: ScanRequest):
    result = classifier(request.text)[0]
    is_spam = result["label"] == "NEGATIVE"
    return {
        "text": request.text,
        "isSpam": is_spam,
        "confidence": result["score"]
    }
