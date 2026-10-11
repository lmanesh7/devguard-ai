from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Demo Cloud Agent API")


class PromptRequest(BaseModel):
    session_id: str
    message: str


@app.post("/chat")
def chat(request: PromptRequest):
    return {"status": "ok", "response": f"Echo: {request.message}"}


@app.get("/health")
def health():
    return {"status": "healthy"}
