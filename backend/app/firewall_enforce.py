"""
Firewall Enforcement Module - Python implementation
Handles firewall actions for detected threats
"""
import os
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import json

class FirewallEnforce:
    """
    Firewall enforcement class for implementing security actions
    """
    
    def __init__(self):
        self.blocked_ips = set()
        self.rate_limits = {}
        self.action_log = []
        self.logger = logging.getLogger(__name__)
        
        # Create data directory for logs
        os.makedirs("data/firewall_logs", exist_ok=True)
        
        print("[Firewall] Firewall enforcement module initialized")
    
    def execute_action(self, flow_id: str, attack_type: str, action: str) -> Dict[str, Any]:
        """
        Execute firewall action based on threat analysis
        
        Args:
            flow_id: Identifier for the network flow (e.g., "IP:PORT")
            attack_type: Type of attack detected
            action: Action to take (BLOCK_IP, RATE_LIMIT, etc.)
        
        Returns:
            Dict containing action result
        """
        timestamp = datetime.now()
        
        try:
            if action == "BLOCK_IP":
                result = self._block_ip(flow_id, attack_type)
            elif action == "RATE_LIMIT":
                result = self._rate_limit(flow_id, attack_type)
            elif action == "MONITOR":
                result = self._monitor(flow_id, attack_type)
            else:
                result = {"status": "unknown_action", "action": action}
            
            # Log the action
            log_entry = {
                "timestamp": timestamp.isoformat(),
                "flow_id": flow_id,
                "attack_type": attack_type,
                "action": action,
                "result": result
            }
            self.action_log.append(log_entry)
            self._save_log(log_entry)
            
            return result
            
        except Exception as e:
            error_msg = f"Firewall action failed: {str(e)}"
            self.logger.error(error_msg)
            return {"status": "error", "message": error_msg}
    
    def _block_ip(self, flow_id: str, attack_type: str) -> Dict[str, Any]:
        """Block an IP address"""
        # Extract IP from flow_id (assuming format "IP:PORT")
        ip_address = flow_id.split(":")[0] if ":" in flow_id else flow_id
        
        self.blocked_ips.add(ip_address)
        
        # In a real implementation, this would add iptables rules
        # For demo purposes, we'll just log it
        print(f"[Firewall] BLOCKED IP: {ip_address} (Attack: {attack_type})")
        
        return {
            "status": "success",
            "action": "BLOCK_IP",
            "ip_address": ip_address,
            "attack_type": attack_type,
            "blocked_at": datetime.now().isoformat()
        }
    
    def _rate_limit(self, flow_id: str, attack_type: str) -> Dict[str, Any]:
        """Apply rate limiting to an IP"""
        ip_address = flow_id.split(":")[0] if ":" in flow_id else flow_id
        
        # Set rate limit (e.g., 10 requests per minute)
        self.rate_limits[ip_address] = {
            "requests_per_minute": 10,
            "set_at": datetime.now().isoformat(),
            "reason": attack_type
        }
        
        print(f"[Firewall] RATE LIMITED IP: {ip_address} (Attack: {attack_type})")
        
        return {
            "status": "success",
            "action": "RATE_LIMIT",
            "ip_address": ip_address,
            "attack_type": attack_type,
            "limit": "10 requests/minute",
            "limited_at": datetime.now().isoformat()
        }
    
    def _monitor(self, flow_id: str, attack_type: str) -> Dict[str, Any]:
        """Monitor a flow without blocking"""
        ip_address = flow_id.split(":")[0] if ":" in flow_id else flow_id
        
        print(f"[Firewall] MONITORING IP: {ip_address} (Attack: {attack_type})")
        
        return {
            "status": "success",
            "action": "MONITOR",
            "ip_address": ip_address,
            "attack_type": attack_type,
            "monitored_at": datetime.now().isoformat()
        }
    
    def log_event(self, flow_id: str, classification: str):
        """Log normal traffic events"""
        timestamp = datetime.now()
        
        log_entry = {
            "timestamp": timestamp.isoformat(),
            "flow_id": flow_id,
            "classification": classification,
            "action": "ALLOW"
        }
        
        self.action_log.append(log_entry)
        print(f"[Firewall] ALLOWED: {flow_id} ({classification})")
    
    def _save_log(self, log_entry: Dict[str, Any]):
        """Save log entry to file"""
        try:
            log_file = f"data/firewall_logs/firewall_{datetime.now().strftime('%Y%m%d')}.json"
            
            # Read existing logs
            logs = []
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            
            # Add new entry
            logs.append(log_entry)
            
            # Save logs
            with open(log_file, 'w') as f:
                json.dump(logs, f, indent=2)
                
        except Exception as e:
            print(f"[Firewall] Failed to save log: {e}")
    
    def get_blocked_ips(self) -> list:
        """Get list of currently blocked IPs"""
        return list(self.blocked_ips)
    
    def get_rate_limits(self) -> Dict[str, Any]:
        """Get current rate limits"""
        return self.rate_limits
    
    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Remove IP from blocked list"""
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            print(f"[Firewall] UNBLOCKED IP: {ip_address}")
            return {"status": "success", "ip_address": ip_address, "action": "UNBLOCK"}
        else:
            return {"status": "error", "message": f"IP {ip_address} not found in blocked list"}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get firewall statistics"""
        return {
            "blocked_ips_count": len(self.blocked_ips),
            "rate_limited_ips_count": len(self.rate_limits),
            "total_actions": len(self.action_log),
            "blocked_ips": list(self.blocked_ips),
            "rate_limited_ips": list(self.rate_limits.keys())
        }
