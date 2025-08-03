from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx

app = FastAPI()

# Configuration
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_API_KEY = "" 

class ChatRequest(BaseModel):
    messages: list[dict]
    model: str = "deepseek-chat"
    temperature: float = 0.7
    max_tokens: int = 1024

@app.post("/chat")
async def chat_with_deepseek(request: ChatRequest):
    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "messages": request.messages,
        "model": request.model,
        "temperature": request.temperature,
        "max_tokens": request.max_tokens
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                DEEPSEEK_API_URL,
                headers=headers,
                json=payload,
                timeout=30.0
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=response.text
                )
            
            return response.json()
    
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Request to DeepSeek API failed: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)