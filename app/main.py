import json
from typing import List
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app.database import get_db, SecurityIncident, BlockedIP, SessionLocal
from app.detector import detector

app = FastAPI(
    title="SentinelAPI AI Security Gateway",
    description="Real-Time Machine Learning API Threat Monitoring System",
    version="1.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- WEBSOCKET CONNECTION MANAGER ---
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
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                pass


manager = ConnectionManager()


# --- REAL-TIME AI SECURITY INSPECTION MIDDLEWARE ---
@app.middleware("http")
async def security_guard_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path

    # Skip internal / static / dashboard endpoints
    if (path.startswith("/static") or 
        path.startswith("/docs") or 
        path.startswith("/openapi.json") or 
        path.startswith("/api/threats") or 
        path.startswith("/ws") or 
        path == "/" or 
        path == "/health"):
        return await call_next(request)

    # 1. IP Blacklist check
    db = SessionLocal()
    try:
        is_blocked = db.query(BlockedIP).filter(
            BlockedIP.ip_address == client_ip, 
            BlockedIP.is_active == True
        ).first()
        if is_blocked:
            return JSONResponse(
                status_code=403,
                content={"error": "Access Denied: Your IP is blacklisted by SentinelAPI Gateway."}
            )
    finally:
        db.close()

    # 2. Extract inspection targets: query values and request body
    query_params_values = " ".join([v for _, v in request.query_params.multi_items()])
    body_text = ""
    try:
        raw_body = await request.body()
        if raw_body:
            body_text = raw_body.decode("utf-8", errors="ignore")
    except Exception:
        pass

    target_content = f"{query_params_values} {body_text}".strip()

    # -------------------------------------------------------------
    # AI / ML Payload Inspection (SQLi, XSS, Cmd, CSIC Anomaly)
    # -------------------------------------------------------------
    ml_result = detector.analyze(target_content)

    is_threat = ml_result["is_threat"]
    threat_type = ml_result["threat_type"]
    confidence = ml_result["confidence"]
    payload_logged = target_content[:300] if target_content else "(clean request)"
    action = "BLOCKED" if is_threat else "ALLOWED"

    # 3. Log to PostgreSQL
    incident_data = {
        "client_ip": client_ip,
        "method": request.method,
        "path": path,
        "attack_type": threat_type if is_threat else "Benign",
        "confidence": confidence,
        "anomaly_score": ml_result.get("anomaly_score", 0.0),
        "payload_sample": payload_logged,
        "action_taken": action
    }

    db = SessionLocal()
    try:
        incident = SecurityIncident(**incident_data)
        db.add(incident)
        db.commit()
        incident_id = incident.id
    finally:
        db.close()

    # 4. Broadcast to live dashboard via WebSocket
    await manager.broadcast({
        "event": "TRAFFIC_EVENT",
        "id": incident_id,
        **incident_data,
        "latency_ms": ml_result["latency_ms"]
    })

    # 5. If Threat: Block immediately with HTTP 403 Forbidden
    if is_threat:
        return JSONResponse(
            status_code=403,
            content={
                "status": "BLOCKED",
                "error": "Access Denied by SentinelAPI AI Security Gateway",
                "threat_type": threat_type,
                "confidence": f"{confidence * 100:.1f}%",
                "inspection_latency": f"{ml_result['latency_ms']} ms"
            }
        )

    # 6. If Clean: Pass through to protected route
    response = await call_next(request)
    response.headers["X-Sentinel-Inspection-Time"] = f"{ml_result['latency_ms']}ms"
    return response


# --- WEBSOCKET ENDPOINT ---
@app.websocket("/ws/threats")
async def websocket_threats_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# --- DASHBOARD TELEMETRY APIS ---
@app.get("/api/threats/stats")
def get_threat_stats(db: Session = Depends(get_db)):
    total_inspected = db.query(SecurityIncident).count()
    total_blocked = db.query(SecurityIncident).filter(SecurityIncident.action_taken == "BLOCKED").count()
    total_allowed = db.query(SecurityIncident).filter(SecurityIncident.action_taken == "ALLOWED").count()

    sqli_count = db.query(SecurityIncident).filter(SecurityIncident.attack_type.contains("SQL")).count()
    xss_count = db.query(SecurityIncident).filter(SecurityIncident.attack_type.contains("XSS")).count()
    cmd_count = db.query(SecurityIncident).filter(SecurityIncident.attack_type.contains("Command")).count()
    other_attacks = total_blocked - (sqli_count + xss_count + cmd_count)

    recent_incidents = (
        db.query(SecurityIncident)
        .order_by(SecurityIncident.timestamp.desc())
        .limit(25)
        .all()
    )

    return {
        "total_inspected": total_inspected,
        "total_blocked": total_blocked,
        "total_allowed": total_allowed,
        "breakdown": {
            "SQLi": sqli_count,
            "XSS": xss_count,
            "Command_Traversal": cmd_count,
            "Anomalous_Attack": max(0, other_attacks)
        },
        "recent_incidents": [
            {
                "id": inc.id,
                "timestamp": inc.timestamp.strftime("%H:%M:%S"),
                "ip": inc.client_ip,
                "path": inc.path,
                "type": inc.attack_type,
                "confidence": f"{inc.confidence * 100:.1f}%",
                "payload": inc.payload_sample,
                "action": inc.action_taken
            }
            for inc in recent_incidents
        ]
    }


# --- PROTECTED SAMPLE ENDPOINTS ---
@app.get("/api/products")
def list_products(search: str = ""):
    return {
        "status": "success",
        "message": f"Showing products matching '{search}'",
        "data": [
            {"id": 1, "item": "Gaming Mouse"},
            {"id": 2, "item": "Mechanical Keyboard"}
        ]
    }

@app.get("/api/orders/{order_id}")
def get_order_details(order_id: str):
    return {
        "status": "success",
        "order_id": order_id,
        "item": "Premium Laptop Stand",
        "total_amount": "$49.99",
        "status": "Shipped"
    }

@app.get("/health")
def health_check():
    return {"status": "online", "protection": "active"}


# Mount static files and serve dashboard
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def serve_dashboard():
    return FileResponse("static/index.html")