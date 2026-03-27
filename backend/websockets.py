from fastapi import WebSocket
from typing import List
import json
import logging

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
            
        json_msg = json.dumps(message)
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json_msg)
            except Exception as e:
                logging.error(f"WebSocket send error: {e}")
                disconnected.append(connection)
                
        for d in disconnected:
            self.disconnect(d)

manager = ConnectionManager()
