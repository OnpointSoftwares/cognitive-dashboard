"""
API Gateway Component - Routes requests between services according to DFD
"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.routing import APIRouter
from fastapi.middleware.cors import CORSMiddleware
import httpx
from typing import Dict, Any
import asyncio

class APIGateway:
    """
    API Gateway that routes requests to appropriate microservices
    according to the DFD architecture
    """
    
    def __init__(self):
        self.app = FastAPI(title="Cognitive Dashboard API Gateway")
        
        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["*"],
        )
        
        self.services = {
            "cognitive_dashboard": "http://localhost:8001",
            "ai_waf": "http://localhost:8002", 
            "firewall": "http://localhost:8003",
            "current_network": "http://localhost:8004"
        }
        self.setup_routes()
    
    def setup_routes(self):
        """Setup routing rules according to DFD"""
        
        @self.app.get("/api/v1/dashboard/{path:path}")
        async def route_to_dashboard(request: Request, path: str):
            """Route to Cognitive Dashboard"""
            return await self.proxy_request("cognitive_dashboard", request)
        
        @self.app.post("/api/v1/waf/{path:path}")
        async def route_to_waf(request: Request, path: str):
            """Route to AI WAF"""
            return await self.proxy_request("ai_waf", request)
        
        @self.app.post("/api/v1/firewall/{path:path}")
        async def route_to_firewall(request: Request, path: str):
            """Route to Firewall"""
            return await self.proxy_request("firewall", request)
        
        @self.app.get("/api/v1/network/{path:path}")
        async def route_to_network(request: Request, path: str):
            """Route to Current Network"""
            return await self.proxy_request("current_network", request)
        
        @self.app.get("/health")
        async def health_check():
            """Gateway health check"""
            return {"status": "API Gateway Operational", "services": list(self.services.keys())}
    
    async def proxy_request(self, service_name: str, request: Request):
        """Proxy request to appropriate service"""
        if service_name not in self.services:
            raise HTTPException(status_code=404, detail=f"Service {service_name} not found")
        
        service_url = self.services[service_name]
        path = request.url.path.split(f"/{service_name}/")[-1]
        url = f"{service_url}/{path}"
        
        async with httpx.AsyncClient() as client:
            try:
                if request.method == "GET":
                    response = await client.get(url, params=request.query_params)
                elif request.method == "POST":
                    response = await client.post(url, json=await request.json())
                else:
                    response = await client.request(request.method, url, content=await request.body())
                
                return response.json()
            except httpx.ConnectError:
                raise HTTPException(status_code=503, detail=f"Service {service_name} unavailable")
    
    def get_app(self):
        """Get FastAPI app instance"""
        return self.app

# Initialize gateway
gateway = APIGateway()
app = gateway.get_app()
