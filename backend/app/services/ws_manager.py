import json
from fastapi import WebSocket


class WSManager:
    def __init__(self):
        self._connections: dict[int, list[WebSocket]] = {}

    async def connect(self, scan_id: int, ws: WebSocket):
        await ws.accept()
        self._connections.setdefault(scan_id, []).append(ws)

    def disconnect(self, scan_id: int, ws: WebSocket):
        conns = self._connections.get(scan_id, [])
        if ws in conns:
            conns.remove(ws)

    async def broadcast(self, scan_id: int, message: dict):
        for ws in self._connections.get(scan_id, []):
            try:
                await ws.send_json(message)
            except Exception:
                pass


ws_manager = WSManager()
