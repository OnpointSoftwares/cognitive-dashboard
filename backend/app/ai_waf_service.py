"""
AI WAF Service - Standalone AI-powered Web Application Firewall
Follows DFD architecture: receives from Cognitive Dashboard, sends to Firewall
"""
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uuid
import numpy as np
from typing import Dict, Any, Optional
import httpx

# Import existing AI detection components
from app.ai_detection_module import MLDetectionModule
from app.firewall_enforce import FirewallEnforce

class WAFRequest(BaseModel):
    """Request model for AI WAF analysis"""
    request_id: Optional[str] = Field(None, description="Unique request identifier")
    source_ip: str = Field(..., description="Source IP address")
    user_agent: str = Field(..., description="User agent string")
    request_method: str = Field(..., description="HTTP method")
    request_uri: str = Field(..., description="Request URI")
    request_body: str = Field(..., description="Request body/payload")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")

class WAFResponse(BaseModel):
    """Response model from AI WAF"""
    request_id: str = Field(..., description="Unique request identifier")
    threat_level: str = Field(..., description="Threat level (LOW, MEDIUM, HIGH, CRITICAL)")
    classification: str = Field(..., description="Threat classification")
    confidence: float = Field(..., description="Confidence score (0.0-1.0)")
    action_taken: str = Field(..., description="Action taken (ALLOW, MONITOR, BLOCK)")
    firewall_action: Optional[Dict[str, Any]] = Field(None, description="Firewall enforcement details")

class AIWAFService:
    """
    AI WAF Service - Standalone microservice for threat detection
    """
    
    def __init__(self):
        self.app = FastAPI(
            title="AI WAF Service",
            description="AI-powered Web Application Firewall microservice"
        )
        
        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["*"],
        )
        
        self.ml_detector = MLDetectionModule()
        self.firewall_enforcer = FirewallEnforce()
        self.network_monitor_url = "http://localhost:8004"  # Current Network service
        self.setup_routes()
    
    def setup_routes(self):
        """Setup WAF service endpoints"""
        
        @self.app.get("/health")
        async def health_check():
            """WAF service health check"""
            return {
                "status": "AI WAF Operational",
                "model_loaded": self.ml_detector.is_model_loaded,
                "firewall_ready": True
            }
        
        @self.app.post("/analyze", response_model=WAFResponse)
        async def analyze_request(request_data: WAFRequest):
            """
            Analyze incoming request for threats using AI
            Follows DFD: Cognitive Dashboard → AI WAF → Firewall
            """
            # Generate request ID if not provided
            request_id = request_data.request_id or str(uuid.uuid4())
            
            try:
                # 1. Extract features from request data
                features = self._extract_features(request_data)
                
                # 2. Get network context from Current Network service
                network_context = await self._get_network_context(request_data.source_ip)
                
                # 3. Combine features with network context
                enhanced_features = self._enhance_features_with_network(features, network_context)
                
                # 4. Run AI detection
                threat_result = self.ml_detector.predict(enhanced_features)
                
                # 5. Determine action based on threat level
                action = self._determine_action(threat_result)
                
                # 6. Execute firewall action if needed
                firewall_action = None
                if action["firewall_action"]:
                    firewall_action = await self._execute_firewall_action(
                        request_id, request_data.source_ip, threat_result, action["firewall_action"]
                    )
                
                return WAFResponse(
                    request_id=request_id,
                    threat_level=action["threat_level"],
                    classification=threat_result["classification"],
                    confidence=threat_result["confidence"],
                    action_taken=action["action_taken"],
                    firewall_action=firewall_action
                )
                
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"WAF analysis failed: {str(e)}"
                )
        
        @self.app.post("/feedback")
        async def receive_network_feedback(feedback_data: Dict[str, Any]):
            """
            Receive feedback from Current Network monitoring
            Follows DFD: Current Network → AI WAF (feedback loop)
            """
            # Update detection model based on network feedback
            # This could involve retraining thresholds, updating patterns, etc.
            return {"status": "feedback_received", "message": "Network feedback processed"}
    
    def _extract_features(self, request_data: WAFRequest) -> np.ndarray:
        """Extract ML features from request data"""
        # Similar to existing calculate_waf_features but adapted for WAF service
        payload_length = len(request_data.request_body)
        
        # User agent scoring
        user_agent_score = 0.95
        if any(bot in request_data.user_agent.lower() for bot in ['bot', 'spider', 'crawler']):
            user_agent_score = 0.1
        elif 'python-requests' in request_data.user_agent.lower():
            user_agent_score = 0.4
        
        # Request rate (will be enhanced with network context)
        request_rate = self.ml_detector.update_rate_tracker(request_data.source_ip)
        
        # Neuro independence score
        neuro_score = user_agent_score * 0.9
        malicious_patterns = ['select * from', 'union all select', '<script>', 'eval(']
        if any(pattern in request_data.request_body.lower() for pattern in malicious_patterns):
            neuro_score = 0.05
        
        return np.array([[user_agent_score, payload_length, request_rate, neuro_score]])
    
    async def _get_network_context(self, source_ip: str) -> Dict[str, Any]:
        """Get network context from Current Network service"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.network_monitor_url}/context/{source_ip}",
                    timeout=2.0
                )
                return response.json()
        except:
            # Fallback if network service is unavailable
            return {"status": "unavailable", "anomaly_score": 0.0}
    
    def _enhance_features_with_network(self, features: np.ndarray, network_context: Dict[str, Any]) -> np.ndarray:
        """Enhance features with network monitoring context"""
        # Add network anomaly score to features
        anomaly_score = network_context.get("anomaly_score", 0.0)
        enhanced_features = features.copy()
        enhanced_features[0][2] = enhanced_features[0][2] * (1 + anomaly_score)  # Boost request rate with anomaly
        return enhanced_features
    
    def _determine_action(self, threat_result: Dict[str, Any]) -> Dict[str, str]:
        """Determine action based on threat analysis"""
        classification = threat_result["classification"]
        confidence = threat_result["confidence"]
        
        if classification == "Normal":
            return {
                "threat_level": "LOW",
                "action_taken": "ALLOW",
                "firewall_action": None
            }
        elif classification == "DDoS_Attack" and confidence > 0.8:
            return {
                "threat_level": "CRITICAL",
                "action_taken": "BLOCK",
                "firewall_action": "BLOCK_IP"
            }
        elif classification == "Intrusion_Attempt" and confidence > 0.7:
            return {
                "threat_level": "HIGH",
                "action_taken": "BLOCK",
                "firewall_action": "BLOCK_IP"
            }
        elif classification == "Neuro_Risk_Flag":
            return {
                "threat_level": "MEDIUM",
                "action_taken": "MONITOR",
                "firewall_action": "RATE_LIMIT"
            }
        else:
            return {
                "threat_level": "MEDIUM",
                "action_taken": "MONITOR",
                "firewall_action": None
            }
    
    async def _execute_firewall_action(self, request_id: str, source_ip: str, threat_result: Dict[str, Any], action: str) -> Dict[str, Any]:
        """Execute firewall action and return result"""
        try:
            # Use existing firewall enforcer
            result = self.firewall_enforcer.execute_action(
                flow_id=f"{source_ip}:{request_id}",
                attack_type=threat_result["classification"],
                action=action
            )
            return {
                "action": action,
                "result": "success",
                "details": result
            }
        except Exception as e:
            return {
                "action": action,
                "result": "failed",
                "error": str(e)
            }
    
    def get_app(self):
        """Get FastAPI app instance"""
        return self.app

# Initialize AI WAF service
ai_waf_service = AIWAFService()
app = ai_waf_service.get_app()
