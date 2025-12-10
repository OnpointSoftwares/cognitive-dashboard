"""
Main Entry Point - Cognitive Security System
Follows DFD Architecture with microservices
"""
import uvicorn
import multiprocessing
import time
from typing import Dict, Any
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import DFD-compliant services
from app.api_gateway import APIGateway
from app.cognitive_dashboard import CognitiveDashboard
from app.ai_waf_service import AIWAFService
from app.current_network_service import CurrentNetworkService
from app.database_service import DatabaseService


class CognitiveSecuritySystem:
    """
    Main orchestrator for the Cognitive Security System
    Follows DFD architecture with microservices
    """
    
    def __init__(self):
        self.services = {}
        self.processes = {}
        self.setup_services()
    
    def setup_services(self):
        """Initialize all DFD-compliant services"""
        # Initialize services
        self.services = {
            'api_gateway': APIGateway(),
            'cognitive_dashboard': CognitiveDashboard(),
            'ai_waf': AIWAFService(),
            'current_network': CurrentNetworkService(),
            'database': DatabaseService()
        }
    
    def start_service(self, service_name, port):
        """Start a single service in its own process"""
        if service_name not in self.services:
            raise ValueError(f"Service {service_name} not found")
        
        service = self.services[service_name]
        app = service.get_app()
        
        # Start service in separate process
        process = multiprocessing.Process(
            target=uvicorn.run,
            args=(app,),
            kwargs={
                'host': '0.0.0.0',
                'port': port,
                'log_level': 'info'
            },
            name=f"{service_name}_service"
        )
        
        process.start()
        self.processes[service_name] = process
        
        print(f"[SYSTEM] {service_name} service started on port {port} (PID: {process.pid})")
        return process
    
    def start_all_services(self):
        """Start all services according to DFD architecture"""
        print("=" * 60)
        print("Starting Cognitive Security System - DFD Architecture")
        print("=" * 60)
        
        # Service ports according to DFD
        service_ports = {
            'api_gateway': 8000,      # Main entry point
            'cognitive_dashboard': 8001,  # User-facing dashboard
            'ai_waf': 8002,           # AI WAF service
            'current_network': 8004,  # Network monitoring
            'database': 8005          # Database service
        }
        
        # Start services in dependency order
        start_order = ['database', 'current_network', 'ai_waf', 'cognitive_dashboard', 'api_gateway']
        
        for service_name in start_order:
            try:
                self.start_service(service_name, service_ports[service_name])
                time.sleep(2)  # Give service time to start
            except Exception as e:
                print(f"[ERROR] Failed to start {service_name}: {e}")
                self.shutdown_all_services()
                return False
        
        print("\n" + "=" * 60)
        print("All services started successfully!")
        print("DFD Architecture Active:")
        print("  User → Web App → API Gateway → Cognitive Dashboard → AI WAF → Firewall")
        print("  AI WAF ↔ Current Network (feedback loop)")
        print("  All components ↔ Database")
        print("=" * 60)
        print("\nService URLs:")
        print(f"  API Gateway: http://localhost:8000")
        print(f"  Dashboard: http://localhost:8001")
        print(f"  AI WAF: http://localhost:8002")
        print(f"  Network Monitor: http://localhost:8004")
        print(f"  Database: http://localhost:8005")
        print("\nPress Ctrl+C to shutdown all services")
        
        return True
    
    def shutdown_all_services(self):
        """Gracefully shutdown all services"""
        print("\n[SYSTEM] Shutting down all services...")
        
        for service_name, process in self.processes.items():
            try:
                process.terminate()
                process.join(timeout=5)
                print(f"[SYSTEM] {service_name} service stopped")
            except Exception as e:
                print(f"[ERROR] Failed to stop {service_name}: {e}")
        
        print("[SYSTEM] All services stopped")
    
    def run(self):
        """Main execution loop"""
        if not self.start_all_services():
            return
        
        try:
            # Keep main process alive
            while True:
                time.sleep(1)
                
                # Check if any service died
                for service_name, process in self.processes.items():
                    if not process.is_alive():
                        print(f"[ERROR] {service_name} service died unexpectedly")
                        self.shutdown_all_services()
                        return
                        
        except KeyboardInterrupt:
            print("\n[SYSTEM] Keyboard interrupt received")
        finally:
            self.shutdown_all_services()


def start_legacy_system():
    """
    Legacy system starter for backward compatibility
    Uses the original multiprocessing approach
    """
    print("[LEGACY] Starting legacy network analysis system...")
    print("[LEGACY] This is the original system before DFD restructuring")
    
    # Import legacy components
    try:
        from backend.src.traffic_sniffer import PacketSniffer
        from backend.app.flow_analyzer import FlowAnalyzer 
        from backend.app.ai_detection_module import AIDetector 
        from backend.app.firewall_enforce import FirewallEnforce
        
        # Legacy configuration
        INTERFACE = "eth0"
        MODEL_PATH = "data/trained_model.pkl"
        SCALER_PATH = "data/model_scaler.pkl"
        TIME_WINDOW = 5
        
        # Initialize legacy components
        packet_queue = multiprocessing.Queue() 
        feature_queue = multiprocessing.Queue()
        
        sniffer = PacketSniffer(interface=INTERFACE, output_queue=packet_queue)
        analyzer = FlowAnalyzer(input_queue=packet_queue, output_queue=feature_queue, time_window=TIME_WINDOW)
        detector = AIDetector(model_path=MODEL_PATH, scaler_path=SCALER_PATH)
        enforcer = FirewallEnforce()

        # Start legacy system
        start_workers(sniffer, analyzer, detector, enforcer, feature_queue)
        
    except ImportError as e:
        print(f"[ERROR] Legacy components not available: {e}")
        print("[INFO] Please use DFD architecture instead")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--legacy":
        # Run legacy system
        start_legacy_system()
    else:
        # Run new DFD-compliant system
        system = CognitiveSecuritySystem()
        system.run()


def start_workers(sniffer, analyzer, detector, enforcer, feature_queue):
    """
    Legacy function for backward compatibility
    Initializes and starts the Sniffer and Analyzer workers as separate processes.
    """
    from queue import Empty
    
    print("[LEGACY] Starting packet sniffing and analysis workers...")
    
    # Start Concurrent Processes (Sniffer and Analyzer)
    sniffer_process = multiprocessing.Process(target=sniffer.start_sniffing, name="SnifferProcess")
    analyzer_process = multiprocessing.Process(target=analyzer.start_analysis, name="AnalyzerProcess")

    sniffer_process.start()
    analyzer_process.start()
    
    print(f"[LEGACY] {sniffer_process.name} PID {sniffer_process.pid} started.")
    print(f"[LEGACY] {analyzer_process.name} PID {analyzer_process.pid} started.")
    print("[LEGACY] AI Detection loop running in main thread...")
    
    # Main Detection and Enforcement Loop
    try:
        while True:
            try:
                feature_vector, flow_id = feature_queue.get(timeout=1) 
            except Empty:
                continue
                
            # Run Inference
            prediction, confidence = detector.predict(feature_vector)

            # Decision Logic and Enforcement
            if prediction != 'Normal' and confidence > 0.95:
                print(f"\n[LEGACY ALERT] **ATTACK DETECTED!** Type: {prediction} | Confidence: {confidence*100:.2f}% | Flow: {flow_id}")
                
                enforcer.execute_action(
                    flow_id=flow_id, 
                    attack_type=prediction, 
                    action='BLOCK_IP'
                )
            else:
                enforcer.log_event(flow_id, prediction)
                
            feature_queue.task_done()
            
    except KeyboardInterrupt:
        print("\n[LEGACY] Keyboard interrupt received. Shutting down workers...")
    
    finally:
        # Graceful Shutdown
        sniffer.stop_sniffing() 
        analyzer.stop_analysis() 

        sniffer_process.join(timeout=5)
        analyzer_process.join(timeout=5)
        
        print("[LEGACY] Shutdown complete.")
