"""
Hugging Face AI Threat Detector
Uses pre-trained models from Hugging Face for threat classification
"""
import os
import json
import asyncio
from typing import Dict, Any, Optional
import numpy as np
from collections import defaultdict, deque
import httpx

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
    import torch
    HUGGINGFACE_AVAILABLE = True
except ImportError:
    HUGGINGFACE_AVAILABLE = False

class HuggingFaceDetector:
    """
    Hugging Face-based threat detection using pre-trained models
    """
    
    def __init__(self):
        self.enabled = HUGGINGFACE_AVAILABLE
        self.models = {}
        self.classifiers = {}
        
        if self.enabled:
            self._load_models()
    
    def _load_models(self):
        """Load pre-trained models"""
        try:
            # Load CyberAttackDetection model for general attack detection
            self.classifiers['attack_detection'] = pipeline(
                "text-classification",
                model="Canstralian/CyberAttackDetection",
                device=0 if torch.cuda.is_available() else -1
            )
            
            # Load malicious URL model for URL-based attacks
            self.classifiers['url_detection'] = pipeline(
                "text-classification", 
                model="r3ddkahili/final-complete-malicious-url-model",
                device=0 if torch.cuda.is_available() else -1
            )
            
            print("Hugging Face models loaded successfully")
            
        except Exception as e:
            print(f"Failed to load Hugging Face models: {e}")
            self.enabled = False
    
    async def analyze_with_huggingface(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze request using Hugging Face models"""
        if not self.enabled:
            return {
                "error": "Hugging Face not available",
                "classification": "API_Error",
                "confidence": 0.0,
                "threat_level": "LOW"
            }
        
        try:
            # Prepare text for analysis
            analysis_text = self._prepare_analysis_text(request_data)
            
            # Get attack detection result
            attack_result = self.classifiers['attack_detection'](analysis_text)
            
            # Get URL detection if URL present
            url_result = None
            if request_data.get('uri'):
                url_text = request_data['uri']
                url_result = self.classifiers['url_detection'](url_text)
            
            # Combine results
            return self._combine_results(attack_result, url_result, request_data)
            
        except Exception as e:
            return {
                "error": f"Hugging Face analysis failed: {str(e)}",
                "classification": "API_Error", 
                "confidence": 0.0,
                "threat_level": "LOW"
            }
    
    def _prepare_analysis_text(self, request_data: Dict[str, Any]) -> str:
        """Prepare request data for analysis"""
        text_parts = []
        
        if request_data.get('method'):
            text_parts.append(f"Method: {request_data['method']}")
        
        if request_data.get('uri'):
            text_parts.append(f"URI: {request_data['uri']}")
        
        if request_data.get('body'):
            text_parts.append(f"Body: {request_data['body'][:500]}")
        
        if request_data.get('user_agent'):
            text_parts.append(f"User-Agent: {request_data['user_agent']}")
        
        return " | ".join(text_parts)
    
    def _combine_results(self, attack_result: Dict, url_result: Optional[Dict], request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Combine results from multiple models"""
        
        # Parse attack detection result
        attack_label = attack_result[0]['label'].lower()
        attack_score = attack_result[0]['score']
        
        # Determine classification
        if 'attack' in attack_label or attack_score > 0.7:
            classification = self._determine_attack_type(request_data)
            threat_level = "HIGH" if attack_score > 0.8 else "MEDIUM"
            confidence = attack_score
            recommended_action = "BLOCK" if attack_score > 0.8 else "MONITOR"
        else:
            classification = "Normal"
            threat_level = "LOW"
            confidence = 1 - attack_score
            recommended_action = "ALLOW"
        
        # Enhance with URL detection if available
        if url_result:
            url_label = url_result[0]['label'].lower()
            url_score = url_result[0]['score']
            
            if url_label != 'benign' and url_score > 0.7:
                classification = f"Malicious_URL_{url_label.title()}"
                threat_level = "HIGH"
                confidence = max(confidence, url_score)
                recommended_action = "BLOCK"
        
        return {
            "classification": classification,
            "threat_level": threat_level,
            "confidence": confidence,
            "reasoning": f"Based on Hugging Face model analysis: {attack_label} (confidence: {attack_score:.2f})",
            "indicators": [attack_label],
            "recommended_action": recommended_action,
            "source": "huggingface",
            "model_results": {
                "attack_detection": attack_result,
                "url_detection": url_result
            }
        }
    
    def _determine_attack_type(self, request_data: Dict[str, Any]) -> str:
        """Determine specific attack type from request data"""
        body = request_data.get('body', '').lower()
        uri = request_data.get('uri', '').lower()
        user_agent = request_data.get('user_agent', '').lower()
        
        # SQL Injection patterns
        sql_patterns = ['union select', 'or 1=1', 'drop table', 'insert into', 'delete from', '--', '/*', '*/']
        if any(pattern in body for pattern in sql_patterns):
            return "SQL_Injection"
        
        # XSS patterns
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', '<iframe', 'eval(']
        if any(pattern in body for pattern in xss_patterns):
            return "XSS"
        
        # Command Injection
        cmd_patterns = ['; ls', '; cat', '| nc', '&&', '||', '`']
        if any(pattern in body for pattern in cmd_patterns):
            return "Command_Injection"
        
        # Path Traversal
        path_patterns = ['../', '..\\', '/etc/passwd', '/windows/system32']
        if any(pattern in uri + body for pattern in path_patterns):
            return "Path_Traversal"
        
        # Bot/Scanner
        bot_patterns = ['sqlmap', 'nikto', 'nmap', 'scanner', 'bot', 'spider', 'crawler']
        if any(pattern in user_agent for pattern in bot_patterns):
            return "Bot_Activity"
        
        return "Suspicious_Activity"

class HybridAIDetector:
    """
    Hybrid detector combining Gemini AI and Hugging Face models
    """
    
    def __init__(self):
        from .gemini_ai_detector import GeminiAIDetector
        self.gemini_detector = GeminiAIDetector()
        self.hf_detector = HuggingFaceDetector()
        
    async def analyze_request(self, request_data: Dict[str, Any], features: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Hybrid analysis using both Gemini and Hugging Face"""
        
        # Try Gemini first
        if self.gemini_detector.enabled:
            gemini_result = await self.gemini_detector.analyze_with_gemini(request_data)
            
            # If Gemini fails, use Hugging Face
            if 'error' in gemini_result or gemini_result.get('classification') in ['API_Error', 'Parse_Error']:
                hf_result = await self.hf_detector.analyze_with_huggingface(request_data)
                return {
                    **hf_result,
                    "analysis_method": "huggingface_fallback",
                    "gemini_error": gemini_result.get('error', 'Gemini API failed')
                }
            
            return {
                **gemini_result,
                "analysis_method": "gemini_primary"
            }
        
        # Use Hugging Face if Gemini not available
        elif self.hf_detector.enabled:
            hf_result = await self.hf_detector.analyze_with_huggingface(request_data)
            return {
                **hf_result,
                "analysis_method": "huggingface_only"
            }
        
        # Fallback to rule-based
        else:
            return {
                "classification": "Normal",
                "confidence": 0.5,
                "threat_level": "LOW",
                "analysis_method": "fallback",
                "recommended_action": "ALLOW",
                "error": "Both Gemini and Hugging Face unavailable"
            }
