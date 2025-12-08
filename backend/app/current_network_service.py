"""
Current Network Service - Network monitoring with feedback loop
Follows DFD: AI WAF → Current Network → AI WAF (feedback loop)
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
import httpx
import asyncio

class NetworkContext(BaseModel):
    """Network context model for IP addresses"""
    ip_address: str = Field(..., description="IP address")
    request_count: int = Field(..., description="Total requests from this IP")
    anomaly_score: float = Field(..., description="Anomaly score (0.0-1.0)")
    last_seen: datetime = Field(..., description="Last activity timestamp")
    reputation_score: float = Field(..., description="IP reputation score")
    geographic_info: Optional[Dict[str, str]] = Field(None, description="Geographic data")

class NetworkEvent(BaseModel):
    """Network event model"""
    event_type: str = Field(..., description="Event type (request, block, anomaly)")
    ip_address: str = Field(..., description="Source IP")
    timestamp: datetime = Field(default_factory=datetime.now, description="Event timestamp")
    details: Dict[str, Any] = Field(default_factory=dict, description="Event details")

class FeedbackData(BaseModel):
    """Feedback data model for AI WAF"""
    ip_address: str = Field(..., description="IP address")
    threat_level: str = Field(..., description="Threat level detected")
    action_taken: str = Field(..., description="Action taken by WAF")
    confidence: float = Field(..., description="Detection confidence")
    timestamp: datetime = Field(default_factory=datetime.now, description="Feedback timestamp")

class CurrentNetworkService:
    """
    Current Network Service - Real-time network monitoring
    Implements feedback loop with AI WAF as shown in DFD
    """
    
    def __init__(self):
        self.app = FastAPI(
            title="Current Network Service",
            description="Real-time network monitoring with AI WAF feedback loop"
        )
        
        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["*"],
        )
        
        # Network monitoring state
        self.ip_profiles: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "request_count": 0,
            "first_seen": datetime.now(),
            "last_seen": datetime.now(),
            "anomaly_score": 0.0,
            "reputation_score": 0.5,  # Neutral start
            "request_times": deque(maxlen=100),  # Last 100 request times
            "blocked_attempts": 0,
            "threat_types": defaultdict(int)
        })
        
        # Network events log
        self.events: List[NetworkEvent] = []
        self.max_events = 10000
        
        # Feedback loop state
        self.ai_waf_url = "http://localhost:8002"
        self.database_url = "http://localhost:8005"
        self.feedback_queue: List[FeedbackData] = []
        
        # Background monitoring thread
        self._monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._background_monitoring, daemon=True)
        self.monitor_thread.start()
        
        self.setup_routes()
    
    def setup_routes(self):
        """Setup network monitoring endpoints"""
        
        @self.app.get("/health")
        async def health_check():
            """Network service health check"""
            return {
                "status": "Current Network Service Operational",
                "monitored_ips": len(self.ip_profiles),
                "total_events": len(self.events),
                "feedback_queue_size": len(self.feedback_queue)
            }
        
        @self.app.get("/context/{ip_address}", response_model=NetworkContext)
        async def get_ip_context(ip_address: str):
            """
            Get network context for an IP address
            Follows DFD: AI WAF → Current Network (context request)
            """
            if ip_address not in self.ip_profiles:
                # Create new profile for unknown IP
                self.ip_profiles[ip_address].update({
                    "first_seen": datetime.now(),
                    "last_seen": datetime.now()
                })
            
            profile = self.ip_profiles[ip_address]
            
            # Calculate current anomaly score
            anomaly_score = self._calculate_anomaly_score(ip_address)
            
            return NetworkContext(
                ip_address=ip_address,
                request_count=profile["request_count"],
                anomaly_score=anomaly_score,
                last_seen=profile["last_seen"],
                reputation_score=profile["reputation_score"],
                geographic_info=self._get_geographic_info(ip_address)
            )
        
        @self.app.post("/track")
        async def track_request(event: NetworkEvent):
            """Track a network request/event"""
            # Update IP profile
            profile = self.ip_profiles[event.ip_address]
            profile["request_count"] += 1
            profile["last_seen"] = event.timestamp
            profile["request_times"].append(event.timestamp)
            
            # Add to events log
            self.events.append(event)
            if len(self.events) > self.max_events:
                self.events.pop(0)
            
            # Store in database
            await self._store_event(event)
            
            return {"status": "tracked", "ip": event.ip_address}
        
        @self.app.post("/feedback")
        async def receive_waf_feedback(feedback: FeedbackData):
            """
            Receive feedback from AI WAF
            Follows DFD: AI WAF → Current Network (feedback loop)
            """
            # Update IP profile based on feedback
            profile = self.ip_profiles[feedback.ip_address]
            
            if feedback.action_taken == "BLOCK":
                profile["blocked_attempts"] += 1
                profile["reputation_score"] = max(0.0, profile["reputation_score"] - 0.1)
            elif feedback.action_taken == "ALLOW" and feedback.threat_level == "LOW":
                profile["reputation_score"] = min(1.0, profile["reputation_score"] + 0.01)
            
            profile["threat_types"][feedback.threat_level] += 1
            
            # Add to feedback queue for processing
            self.feedback_queue.append(feedback)
            
            # Process feedback asynchronously
            asyncio.create_task(self._process_feedback(feedback))
            
            return {"status": "feedback_received", "ip": feedback.ip_address}
        
        @self.app.get("/anomalies")
        async def get_anomalous_ips(threshold: float = 0.7):
            """Get IPs with anomaly scores above threshold"""
            anomalous_ips = []
            for ip, profile in self.ip_profiles.items():
                anomaly_score = self._calculate_anomaly_score(ip)
                if anomaly_score >= threshold:
                    anomalous_ips.append({
                        "ip": ip,
                        "anomaly_score": anomaly_score,
                        "request_count": profile["request_count"],
                        "blocked_attempts": profile["blocked_attempts"],
                        "reputation_score": profile["reputation_score"]
                    })
            
            return {
                "threshold": threshold,
                "anomalous_count": len(anomalous_ips),
                "anomalous_ips": sorted(anomalous_ips, key=lambda x: x["anomaly_score"], reverse=True)
            }
        
        @self.app.get("/stats")
        async def get_network_stats():
            """Get comprehensive network statistics"""
            total_requests = sum(profile["request_count"] for profile in self.ip_profiles.values())
            total_blocks = sum(profile["blocked_attempts"] for profile in self.ip_profiles.values())
            
            # Calculate average anomaly score
            anomaly_scores = [self._calculate_anomaly_score(ip) for ip in self.ip_profiles]
            avg_anomaly = sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else 0.0
            
            return {
                "monitored_ips": len(self.ip_profiles),
                "total_requests": total_requests,
                "total_blocks": total_blocks,
                "block_rate": total_blocks / max(total_requests, 1),
                "average_anomaly_score": avg_anomaly,
                "high_risk_ips": len([score for score in anomaly_scores if score > 0.7]),
                "recent_events": len([e for e in self.events if e.timestamp > datetime.now() - timedelta(hours=1)])
            }
    
    def _calculate_anomaly_score(self, ip_address: str) -> float:
        """Calculate anomaly score for an IP based on various factors"""
        profile = self.ip_profiles[ip_address]
        
        # Factor 1: Request rate anomaly
        recent_requests = [t for t in profile["request_times"] if t > datetime.now() - timedelta(minutes=5)]
        request_rate = len(recent_requests) / 5.0  # requests per minute
        rate_anomaly = min(1.0, request_rate / 60.0)  # Normalize to 0-1 (60 req/min = 1.0)
        
        # Factor 2: Block ratio anomaly
        block_ratio = profile["blocked_attempts"] / max(profile["request_count"], 1)
        block_anomaly = min(1.0, block_ratio * 5)  # Amplify block ratio impact
        
        # Factor 3: Reputation anomaly
        reputation_anomaly = 1.0 - profile["reputation_score"]
        
        # Factor 4: Time-based anomaly (requests at unusual hours)
        current_hour = datetime.now().hour
        time_anomaly = 0.3 if current_hour < 6 or current_hour > 22 else 0.0
        
        # Combine factors with weights
        anomaly_score = (
            rate_anomaly * 0.3 +
            block_anomaly * 0.4 +
            reputation_anomaly * 0.2 +
            time_anomaly * 0.1
        )
        
        return min(1.0, anomaly_score)
    
    def _get_geographic_info(self, ip_address: str) -> Optional[Dict[str, str]]:
        """Get geographic information for IP (mock implementation)"""
        # In production, this would use a GeoIP service
        return {
            "country": "Unknown",
            "city": "Unknown",
            "asn": "Unknown"
        }
    
    async def _store_event(self, event: NetworkEvent):
        """Store network event in database"""
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{self.database_url}/store",
                    json={
                        "collection": "network_events",
                        "data": event.dict()
                    },
                    timeout=5.0
                )
        except:
            pass  # Don't fail if database is unavailable
    
    async def _process_feedback(self, feedback: FeedbackData):
        """
        Process WAF feedback and potentially send updates back
        Follows DFD: Current Network → AI WAF (feedback loop completion)
        """
        # Analyze feedback patterns
        profile = self.ip_profiles[feedback.ip_address]
        
        # If this IP shows consistent malicious behavior, proactively inform WAF
        if profile["blocked_attempts"] > 5 and profile["reputation_score"] < 0.2:
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(
                        f"{self.ai_waf_url}/feedback",
                        json={
                            "ip_address": feedback.ip_address,
                            "risk_level": "HIGH",
                            "recommendation": "PREEMPTIVE_BLOCK",
                            "reason": "Consistent malicious behavior detected",
                            "network_context": {
                                "blocked_attempts": profile["blocked_attempts"],
                                "reputation_score": profile["reputation_score"],
                                "anomaly_score": self._calculate_anomaly_score(feedback.ip_address)
                            }
                        },
                        timeout=5.0
                    )
            except:
                pass  # Don't fail if WAF is unavailable
    
    def _background_monitoring(self):
        """Background thread for continuous network monitoring"""
        while self._monitoring_active:
            try:
                # Clean up old IP profiles (inactive for more than 24 hours)
                cutoff_time = datetime.now() - timedelta(hours=24)
                inactive_ips = [
                    ip for ip, profile in self.ip_profiles.items()
                    if profile["last_seen"] < cutoff_time
                ]
                
                for ip in inactive_ips:
                    del self.ip_profiles[ip]
                
                # Sleep for 5 minutes before next cleanup
                time.sleep(300)
                
            except Exception as e:
                print(f"Background monitoring error: {e}")
                time.sleep(60)  # Wait 1 minute on error
    
    def get_app(self):
        """Get FastAPI app instance"""
        return self.app

# Initialize Current Network Service
network_service = CurrentNetworkService()
app = network_service.get_app()
