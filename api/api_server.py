# Run a Local FastAPI Server on Port 8000

from fastapi import FastAPI, Request
import uvicorn

app = FastAPI()

@app.post("/api/alert")
async def receive_alert(request: Request):
    data = await request.json()
    print("🚨 Alert received:", data)
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=True)
