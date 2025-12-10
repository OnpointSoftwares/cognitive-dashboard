"""
Gemini AI Detector - Enhanced threat detection using Google Gemini API
Integrates with existing ML model for hybrid classification approach
"""
import os
import json
import time
import asyncio
import aiohttp
from typing import Dict, Any, Optional, List
from datetime import datetime
import numpy as np
from collections import defaultdict, deque

class GeminiAIDetector:
    """
    Enhanced AI threat detection using Google Gemini API
    Combines traditional ML with LLM-based analysis for better accuracy
    """
    
    def __init__(self):
        self.api_key = os.getenv('GEMINI_API_KEY')
        self.base_url = "https://generativelanguage.googleapis.com/v1/models"
        self.model_name = "gemini-2.5-flash"
        self.enabled = bool(self.api_key)
        
        # Rate limiting for Gemini API
        self.request_timestamps = defaultdict(lambda: deque(maxlen=60))  # Track last 60 seconds
        self.max_requests_per_minute = 60
        
        # Cache for recent analyses to avoid duplicate API calls
        self.analysis_cache = {}
        self.cache_ttl = 300  # 5 minutes cache
        
        print(f"Gemini AI Detector initialized. API Key configured: {bool(self.api_key)}")
        
    def _get_rate_limit_status(self, ip_address: str = "global") -> tuple[bool, float]:
        """Check if we're within rate limits"""
        current_time = time.time()
        timestamps = self.request_timestamps[ip_address]
        
        # Clean old timestamps (older than 60 seconds)
        timestamps = deque([t for t in timestamps if current_time - t < 60], maxlen=60)
        self.request_timestamps[ip_address] = timestamps
        
        # Check if we can make a request
        if len(timestamps) < self.max_requests_per_minute:
            return True, 0.0
        
        # Calculate wait time
        oldest_request = timestamps[0]
        wait_time = 60 - (current_time - oldest_request)
        return False, max(0, wait_time)
    
    def _get_cache_key(self, request_data: Dict[str, Any]) -> str:
        """Generate cache key for request data"""
        # Create a normalized string representation
        key_data = {
            'uri': request_data.get('uri', ''),
            'method': request_data.get('method', ''),
            'body_length': len(request_data.get('body', '')),
            'user_agent': request_data.get('user_agent', '')[:50],  # First 50 chars
            'headers_count': len(request_data.get('headers', {}))
        }
        return str(hash(json.dumps(key_data, sort_keys=True)))
    
    def _is_cached(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Check if analysis is cached and still valid"""
        if cache_key in self.analysis_cache:
            cached_data = self.analysis_cache[cache_key]
            if time.time() - cached_data['timestamp'] < self.cache_ttl:
                return cached_data['result']
            else:
                del self.analysis_cache[cache_key]
        return None
    
    def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache analysis result"""
        self.analysis_cache[cache_key] = {
            'result': result,
            'timestamp': time.time()
        }
    
    async def analyze_with_gemini(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze request using Gemini API for enhanced threat detection
        """
        if not self.enabled:
            return {
                "error": "Gemini API not configured. Set GEMINI_API_KEY environment variable.",
                "classification": "Unknown",
                "confidence": 0.0,
                "threat_level": "LOW"
            }
        
        # Check rate limiting
        can_proceed, wait_time = self._get_rate_limit_status()
        if not can_proceed:
            return {
                "error": f"Rate limit exceeded. Wait {wait_time:.1f} seconds.",
                "classification": "Rate_Limited",
                "confidence": 0.0,
                "threat_level": "MEDIUM"
            }
        
        # Check cache
        cache_key = self._get_cache_key(request_data)
        cached_result = self._is_cached(cache_key)
        if cached_result:
            return cached_result
        
        # Prepare analysis prompt
        prompt = self._create_analysis_prompt(request_data)
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/{self.model_name}:generateContent?key={self.api_key}"
                
                payload = {
                    "contents": [{
                        "parts": [{
                            "text": prompt
                        }]
                    }],
                    "generationConfig": {
                        "temperature": 0.1,
                        "topK": 32,
                        "topP": 0.95,
                        "maxOutputTokens": 2048,
                    }
                }
                
                async with session.post(url, json=payload, timeout=30) as response:
                    if response.status == 200:
                        result = await response.json()
                        analysis = self._parse_gemini_response(result)
                        self._cache_result(cache_key, analysis)
                        return analysis
                    else:
                        error_text = await response.text()
                        return {
                            "error": f"Gemini API error: {response.status} - {error_text}",
                            "classification": "API_Error",
                            "confidence": 0.0,
                            "threat_level": "LOW"
                        }
                        
        except asyncio.TimeoutError:
            return {
                "error": "Gemini API timeout",
                "classification": "Timeout",
                "confidence": 0.0,
                "threat_level": "LOW"
            }
        except Exception as e:
            return {
                "error": f"Gemini API exception: {str(e)}",
                "classification": "Exception",
                "confidence": 0.0,
                "threat_level": "LOW"
            }
    
    def _create_analysis_prompt(self, request_data: Dict[str, Any]) -> str:
        """Create analysis prompt for Gemini"""
        prompt = f"""Analyze this HTTP request for security threats:

Method: {request_data.get('method', 'Unknown')}
URI: {request_data.get('uri', 'Unknown')}
Source IP: {request_data.get('source_ip', 'Unknown')}
User Agent: {request_data.get('user_agent', 'Unknown')}
Request Body: {request_data.get('body', '')[:500]}

Return JSON: {{"classification": "SQL_Injection|XSS|Command_Injection|Path_Traversal|DDoS_Attack|Brute_Force|Bot_Activity|Normal", "threat_level": "LOW|MEDIUM|HIGH|CRITICAL", "confidence": 0.0-1.0, "reasoning": "Brief explanation", "indicators": ["pattern1", "pattern2"], "recommended_action": "ALLOW|MONITOR|BLOCK"}}"""
        return prompt
    
    def _parse_gemini_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Gemini API response"""
        try:
            content = response.get('candidates', [{}])[0].get('content', {})
            text = content.get('parts', [{}])[0].get('text', '')
            
            # Extract JSON from response
            start_idx = text.find('{')
            end_idx = text.rfind('}') + 1
            
            if start_idx != -1 and end_idx != -1:
                json_str = text[start_idx:end_idx]
                analysis = json.loads(json_str)
                
                # Validate required fields
                required_fields = ['classification', 'threat_level', 'confidence', 'reasoning', 'indicators', 'recommended_action']
                for field in required_fields:
                    if field not in analysis:
                        analysis[field] = "Unknown" if field != 'confidence' else 0.0
                
                # Ensure confidence is float
                try:
                    analysis['confidence'] = float(analysis['confidence'])
                except:
                    analysis['confidence'] = 0.5
                
                # Ensure indicators is list
                if not isinstance(analysis['indicators'], list):
                    analysis['indicators'] = [str(analysis['indicators'])]
                
                return {
                    "classification": analysis['classification'],
                    "threat_level": analysis['threat_level'],
                    "confidence": analysis['confidence'],
                    "reasoning": analysis['reasoning'],
                    "indicators": analysis['indicators'],
                    "recommended_action": analysis['recommended_action'],
                    "source": "gemini_ai"
                }
            else:
                raise ValueError("No JSON found in response")
                
        except Exception as e:
            return {
                "error": f"Failed to parse Gemini response: {str(e)}",
                "classification": "Parse_Error",
                "confidence": 0.0,
                "threat_level": "LOW",
                "source": "gemini_ai"
            }

class GeminiOnlyDetector:
    """
    Gemini-only AI threat detector
    Uses Google Gemini API exclusively for threat analysis
    """
    
    def __init__(self):
        self.gemini_detector = GeminiAIDetector()
        
    async def analyze_request(self, request_data: Dict[str, Any], features: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """
        Gemini-only analysis
        """
        if self.gemini_detector.enabled:
            # Use Gemini for analysis
            gemini_result = await self.gemini_detector.analyze_with_gemini(request_data)
            
            return {
                **gemini_result,
                "analysis_method": "gemini_only",
                "final_classification": gemini_result.get('classification', 'Unknown'),
                "final_confidence": gemini_result.get('confidence', 0.0),
                "final_threat_level": gemini_result.get('threat_level', 'LOW'),
                "recommended_action": gemini_result.get('recommended_action', 'MONITOR')
            }
        else:
            # Fallback classification when Gemini not available
            return {
                "classification": "Normal",
                "confidence": 0.5,
                "threat_level": "LOW",
                "analysis_method": "fallback",
                "recommended_action": "ALLOW",
                "error": "Gemini API not configured"
            }
    
    def _get_action_from_ml_result(self, ml_result: Dict[str, Any]) -> str:
        """Convert ML result to recommended action"""
        classification = ml_result.get('classification', 'Normal')
        confidence = ml_result.get('confidence', 0.0)
        
        if classification == 'Normal':
            return 'ALLOW'
        elif classification in ['DDoS_Attack', 'Intrusion_Attempt'] and confidence > 0.7:
            return 'BLOCK'
        else:
            return 'MONITOR'
