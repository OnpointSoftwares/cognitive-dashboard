"""
Local Security Threat Detector
Uses locally trained models for threat classification
"""
import os
import joblib
import numpy as np
from typing import Dict, Any, Optional
from .local_classifier_trainer import SecurityClassifierTrainer

class LocalSecurityDetector:
    """
    Local model-based threat detection
    """
    
    def __init__(self):
        self.trainer = SecurityClassifierTrainer()
        self.enabled = self.trainer.load_models()
        self.current_model = 'random_forest'  # Default best performing model
        
    async def analyze_request(self, request_data: Dict[str, Any], features: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Analyze request using local models"""
        
        if not self.enabled:
            return {
                "error": "Local models not loaded",
                "classification": "Model_Error",
                "confidence": 0.0,
                "threat_level": "LOW",
                "analysis_method": "local_model_failed"
            }
        
        try:
            # Prepare analysis text
            analysis_text = self._prepare_request_text(request_data)
            
            # Get prediction from best model
            result = self.trainer.predict(analysis_text, self.current_model)
            
            # Enhance with rule-based analysis
            enhanced_result = self._enhance_with_rules(request_data, result)
            
            return {
                **enhanced_result,
                "analysis_method": "local_model",
                "model_used": self.current_model,
                "source": "local_trained_model"
            }
            
        except Exception as e:
            return {
                "error": f"Local model analysis failed: {str(e)}",
                "classification": "Model_Error",
                "confidence": 0.0,
                "threat_level": "LOW",
                "analysis_method": "local_model_error"
            }
    
    def _prepare_request_text(self, request_data: Dict[str, Any]) -> str:
        """Prepare request data for analysis"""
        parts = []
        
        if request_data.get('method'):
            parts.append(f"Method: {request_data['method']}")
        
        if request_data.get('uri'):
            parts.append(f"URI: {request_data['uri']}")
        
        if request_data.get('body'):
            parts.append(f"Body: {request_data['body']}")
        
        if request_data.get('user_agent'):
            parts.append(f"User-Agent: {request_data['user_agent']}")
        
        return " | ".join(parts)
    
    def _enhance_with_rules(self, request_data: Dict[str, Any], model_result: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance model prediction with rule-based analysis"""
        
        body = request_data.get('body', '').lower()
        uri = request_data.get('uri', '').lower()
        user_agent = request_data.get('user_agent', '').lower()
        
        # Check for specific attack patterns
        indicators = []
        
        # SQL Injection patterns
        sql_patterns = ['union select', 'or 1=1', 'drop table', 'insert into', '--', '/*', '*/']
        sql_matches = [pattern for pattern in sql_patterns if pattern in body]
        if sql_matches:
            indicators.extend([f"SQL pattern: {pattern}" for pattern in sql_matches])
            if model_result['classification'] != 'SQL_Injection':
                model_result['classification'] = 'SQL_Injection'
                model_result['threat_level'] = 'HIGH'
                model_result['confidence'] = max(model_result['confidence'], 0.8)
        
        # XSS patterns
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', '<iframe', 'eval(']
        xss_matches = [pattern for pattern in xss_patterns if pattern in body]
        if xss_matches:
            indicators.extend([f"XSS pattern: {pattern}" for pattern in xss_matches])
            if model_result['classification'] != 'XSS':
                model_result['classification'] = 'XSS'
                model_result['threat_level'] = 'HIGH'
                model_result['confidence'] = max(model_result['confidence'], 0.7)
        
        # Command Injection patterns
        cmd_patterns = ['; ls', '| cat', '&& rm', '`whoami`', '|| nc']
        cmd_matches = [pattern for pattern in cmd_patterns if pattern in body]
        if cmd_matches:
            indicators.extend([f"Command pattern: {pattern}" for pattern in cmd_matches])
            if model_result['classification'] != 'Command_Injection':
                model_result['classification'] = 'Command_Injection'
                model_result['threat_level'] = 'HIGH'
                model_result['confidence'] = max(model_result['confidence'], 0.8)
        
        # Path Traversal patterns
        path_patterns = ['../', '..\\', '/etc/passwd', '/windows/system32']
        path_matches = [pattern for pattern in path_patterns if pattern in uri + body]
        if path_matches:
            indicators.extend([f"Path pattern: {pattern}" for pattern in path_matches])
            if model_result['classification'] != 'Path_Traversal':
                model_result['classification'] = 'Path_Traversal'
                model_result['threat_level'] = 'HIGH'
                model_result['confidence'] = max(model_result['confidence'], 0.8)
        
        # Bot/Scanner patterns
        bot_patterns = ['sqlmap', 'nikto', 'nmap', 'scanner', 'bot', 'spider', 'crawler']
        bot_matches = [pattern for pattern in bot_patterns if pattern in user_agent]
        if bot_matches:
            indicators.extend([f"Bot pattern: {pattern}" for pattern in bot_matches])
            if model_result['classification'] != 'Bot_Activity':
                model_result['classification'] = 'Bot_Activity'
                model_result['threat_level'] = 'MEDIUM'
                model_result['confidence'] = max(model_result['confidence'], 0.6)
        
        # Add reasoning and indicators
        model_result['reasoning'] = f"Local model prediction enhanced with rule-based analysis. Model predicted: {model_result['classification']}"
        model_result['indicators'] = indicators if indicators else ['Model prediction']
        
        # Determine recommended action
        if model_result['threat_level'] in ['HIGH', 'CRITICAL']:
            model_result['recommended_action'] = 'BLOCK'
        elif model_result['threat_level'] == 'MEDIUM':
            model_result['recommended_action'] = 'MONITOR'
        else:
            model_result['recommended_action'] = 'ALLOW'
        
        return model_result
    
    def switch_model(self, model_name: str) -> bool:
        """Switch to different model"""
        if model_name in self.trainer.models:
            self.current_model = model_name
            print(f"Switched to model: {model_name}")
            return True
        return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about available models"""
        return {
            'current_model': self.current_model,
            'available_models': list(self.trainer.models.keys()),
            'models_loaded': self.enabled,
            'model_details': {
                name: {
                    'accuracy': result['accuracy'],
                    'type': type(result['model']).__name__
                }
                for name, result in self.trainer.models.items()
            }
        }

class HybridLocalDetector:
    """
    Hybrid detector combining local models with Gemini and Hugging Face
    Priority: Local Models -> Hugging Face -> Gemini -> Rules
    """
    
    def __init__(self):
        from .local_security_detector import LocalSecurityDetector
        from .huggingface_detector import HybridAIDetector
        from .gemini_ai_detector import GeminiAIDetector
        
        self.local_detector = LocalSecurityDetector()
        self.hf_detector = HybridAIDetector()
        self.gemini_detector = GeminiAIDetector()
        
    async def analyze_request(self, request_data: Dict[str, Any], features: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Hierarchical analysis with multiple fallbacks"""
        
        # 1. Try local models first (fastest, no API limits)
        if self.local_detector.enabled:
            try:
                result = await self.local_detector.analyze_request(request_data, features)
                if 'error' not in result:
                    return {
                        **result,
                        "analysis_method": "local_model_primary",
                        "detection_tier": "1"
                    }
            except Exception as e:
                print(f"Local model failed: {e}")
        
        # 2. Try Hugging Face models
        if self.hf_detector.hf_detector.enabled:
            try:
                result = await self.hf_detector.analyze_request(request_data, features)
                if 'error' not in result:
                    return {
                        **result,
                        "analysis_method": "huggingface_fallback",
                        "detection_tier": "2"
                    }
            except Exception as e:
                print(f"Hugging Face failed: {e}")
        
        # 3. Try Gemini as last resort
        if self.gemini_detector.enabled:
            try:
                result = await self.gemini_detector.analyze_with_gemini(request_data)
                if 'error' not in result:
                    return {
                        **result,
                        "analysis_method": "gemini_fallback",
                        "detection_tier": "3"
                    }
            except Exception as e:
                print(f"Gemini failed: {e}")
        
        # 4. Final fallback to rule-based
        return {
            "classification": "Normal",
            "confidence": 0.5,
            "threat_level": "LOW",
            "analysis_method": "rule_based_fallback",
            "detection_tier": "4",
            "recommended_action": "ALLOW",
            "reasoning": "All detection methods failed, using default safe classification"
        }
