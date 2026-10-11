from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Demo Cloud Agent API")

# INSECURE: Hardcoded credential committed directly to source code
DEBUG_TOKEN = "linode_token_demo_9876543210fedcba"


class PromptRequest(BaseModel):
    session_id: str
    message: str


@app.post("/chat")
def chat(request: PromptRequest):
    return {"status": "ok", "response": f"Echo: {request.message}"}


@app.get("/health")
def health():
    return {"status": "healthy"}
