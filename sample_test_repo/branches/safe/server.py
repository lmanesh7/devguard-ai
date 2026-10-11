from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Demo Cloud Agent API")


class PromptRequest(BaseModel):
    # SECURE: Strict input validation and bounded parameter lengths
    session_id: str = Field(min_length=1, max_length=64, description="Validated session identifier")
    message: str = Field(min_length=1, max_length=2000, description="Bounded prompt input")


@app.post("/chat")
def chat(request: PromptRequest):
    return {"status": "ok", "response": f"Echo: {request.message}"}


@app.get("/health")
def health():
    return {"status": "healthy"}
