"""
Cognitive Dashboard Service - Main dashboard service
Follows DFD: API Gateway → Cognitive Dashboard → AI WAF
"""
from fastapi import FastAPI, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import httpx
import uuid
from app.ai_detection_module import MLDetectionModule
from datetime import datetime

class UserRequest(BaseModel):
    """User request model for dashboard"""
    user_id: str = Field(..., description="User identifier")
    request_data: Dict[str, Any] = Field(..., description="Request payload")

class DashboardResponse(BaseModel):
    """Dashboard response model"""
    request_id: str = Field(..., description="Unique request identifier")
    status: str = Field(..., description="Request status")
    waf_result: Optional[Dict[str, Any]] = Field(None, description="WAF analysis result")
    timestamp: datetime = Field(..., description="Response timestamp")

class SystemMetrics(BaseModel):
    """System metrics model"""
    total_requests: int = Field(..., description="Total requests processed")
    blocked_requests: int = Field(..., description="Total blocked requests")
    active_threats: int = Field(..., description="Currently active threats")
    system_health: str = Field(..., description="Overall system health")

class CognitiveDashboard:
    """
    Cognitive Dashboard Service - Main interface for users
    Follows DFD architecture
    """
    
    def __init__(self):
        self.app = FastAPI(
            title="Cognitive Dashboard",
            description="Main cognitive security dashboard service"
        )
        
        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["*"],
        )
        
        self.ai_waf_url = "http://localhost:8002"
        self.database_url = "http://localhost:8005"
        self.request_history: List[Dict[str, Any]] = []
        self.metrics = {
            "total_requests": 0,
            "blocked_requests": 0,
            "active_threats": 0
        }
        self.setup_routes()
    
    def setup_routes(self):
        """Setup dashboard endpoints"""
        
        @self.app.get("/health")
        async def health_check():
            """Dashboard health check"""
            return {
                "status": "Cognitive Dashboard Operational",
                "metrics": self.metrics,
                "services": ["ai_waf", "database"]
            }
        
        @self.app.post("/process", response_model=DashboardResponse)
        async def process_user_request(request: UserRequest):
            """
            Process user request through AI WAF
            Follows DFD: User → Web App → API Gateway → Cognitive Dashboard → AI WAF
            """
            request_id = str(uuid.uuid4())
            timestamp = datetime.now()
            
            try:
                # Update metrics
                self.metrics["total_requests"] += 1
                
                # Prepare WAF request
                waf_request = {
                    "request_id": request_id,
                    "source_ip": request.request_data.get("source_ip", "unknown"),
                    "user_agent": request.request_data.get("user_agent", ""),
                    "request_method": request.request_data.get("method", "GET"),
                    "request_uri": request.request_data.get("uri", "/"),
                    "request_body": request.request_data.get("body", ""),
                    "headers": request.request_data.get("headers", {})
                }
                
                # Send to AI WAF for analysis
                async with httpx.AsyncClient() as client:
                    waf_response = await client.post(
                        f"{self.ai_waf_url}/analyze",
                        json=waf_request,
                        timeout=10.0
                    )
                    waf_result = waf_response.json()
                
                # Update metrics based on WAF result
                if waf_result.get("action_taken") == "BLOCK":
                    self.metrics["blocked_requests"] += 1
                
                # Store request in history
                history_entry = {
                    "request_id": request_id,
                    "user_id": request.user_id,
                    "timestamp": timestamp,
                    "waf_result": waf_result
                }
                self.request_history.append(history_entry)
                
                # Store in database
                await self._store_in_database(history_entry)
                
                return DashboardResponse(
                    request_id=request_id,
                    status="processed",
                    waf_result=waf_result,
                    timestamp=timestamp
                )
                
            except httpx.ConnectError:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="AI WAF service unavailable"
                )
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Request processing failed: {str(e)}"
                )
        
        @self.app.get("/metrics", response_model=SystemMetrics)
        async def get_system_metrics():
            """Get system metrics and health"""
            # Determine system health
            health = "HEALTHY"
            if self.metrics["blocked_requests"] / max(self.metrics["total_requests"], 1) > 0.1:
                health = "WARNING"
            if self.metrics["active_threats"] > 10:
                health = "CRITICAL"
            
            return SystemMetrics(
                total_requests=self.metrics["total_requests"],
                blocked_requests=self.metrics["blocked_requests"],
                active_threats=self.metrics["active_threats"],
                system_health=health
            )
        
        @self.app.get("/history")
        async def get_request_history(
            limit: int = Query(100, description="Number of recent requests to return"),
            user_id: Optional[str] = Query(None, description="Filter by user ID")
        ):
            """Get request history with optional filtering"""
            history = self.request_history
            
            if user_id:
                history = [req for req in history if req.get("user_id") == user_id]
            
            # Return most recent requests
            return sorted(history, key=lambda x: x["timestamp"], reverse=True)[:limit]
        
        @self.app.get("/dashboard")
        async def get_dashboard_data():
            """Get comprehensive dashboard data"""
            return {
                "metrics": await get_system_metrics(),
                "recent_activity": await get_request_history(limit=10),
                "threat_summary": await self._get_threat_summary(),
                "system_status": {
                    "ai_waf": await self._check_service_health(self.ai_waf_url),
                    "database": await self._check_service_health(self.database_url)
                }
            }
        
        @self.app.post("/admin/trigger-scan")
        async def trigger_security_scan():
            """Admin endpoint to trigger security scan"""
            # This would trigger a comprehensive security scan
            return {"status": "scan_initiated", "message": "Security scan started"}
    
    async def _store_in_database(self, data: Dict[str, Any]):
        """Store data in database service"""
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{self.database_url}/store",
                    json=data,
                    timeout=5.0
                )
        except:
            # Log error but don't fail the request
            pass
    
    async def _get_threat_summary(self) -> Dict[str, Any]:
        """Get threat summary from recent requests"""
        recent_threats = []
        for req in self.request_history[-100:]:  # Last 100 requests
            waf_result = req.get("waf_result", {})
            if waf_result.get("classification") != "Normal":
                recent_threats.append({
                    "timestamp": req["timestamp"],
                    "threat_type": waf_result.get("classification"),
                    "confidence": waf_result.get("confidence"),
                    "action": waf_result.get("action_taken")
                })
        
        return {
            "total_threats": len(recent_threats),
            "recent_threats": recent_threats[:10]  # Last 10 threats
        }
    
    async def _check_service_health(self, service_url: str) -> str:
        """Check health of a service"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{service_url}/health", timeout=2.0)
                return "HEALTHY" if response.status_code == 200 else "UNHEALTHY"
        except:
            return "UNREACHABLE"
    
    def get_app(self):
        """Get FastAPI app instance"""
        return self.app

# Initialize Cognitive Dashboard
dashboard = CognitiveDashboard()
app = dashboard.get_app()
