from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .database import engine, Base, get_db
from .models import PacketLog, Alert
from .websockets import manager

# Create DB tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Explainable AI IDS Platform")

# Allow React app front-end to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For production, set this to frontend localhost url
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    from .capture import start_sniffer, process_packets
    import asyncio
    start_sniffer()
    asyncio.create_task(process_packets())

@app.get("/")
def read_root():
    return {"status": "Explainable API IDS Backend Running"}

@app.post("/api/engine/toggle")
async def toggle_engine_route():
    from .capture import toggle_engine
    state = await toggle_engine()
    return {"status": "success", "state": state}

@app.websocket("/ws/traffic")
async def websocket_traffic(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; messages will be broadcasted from packet sniffer
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/api/logs")
def get_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    logs = db.query(PacketLog).order_by(PacketLog.timestamp.desc()).offset(skip).limit(limit).all()
    return logs

@app.get("/api/alerts")
def get_alerts(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).offset(skip).limit(limit).all()
    return alerts

if __name__ == "__main__":
    import uvicorn
    import multiprocessing
    multiprocessing.freeze_support()
    uvicorn.run(app, host="127.0.0.1", port=8006)
