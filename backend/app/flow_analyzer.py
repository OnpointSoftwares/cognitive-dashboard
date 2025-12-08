import time
import threading
from queue import Queue, Empty
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP
import pandas as pd
import numpy as np

# --- Placeholder for Feature Mapping ---
# NOTE: In a real project, this would be a large, static list 
# containing all 41/78 features from your NSL-KDD or CICIDS2017 dataset.
REAL_TIME_FEATURES = [
    'flow_id', 'packet_count', 'byte_count', 'duration_sec', 
    'max_pkt_size', 'avg_pkt_size', 'is_tcp_fin_flag', 'is_flow_active'
]

class FlowAnalyzer:
    """
    Reads raw packets from the input queue, aggregates them into network flows, 
    calculates real-time features, and puts the ready feature vectors into 
    the output queue for the AI Detector.
    """

    def __init__(self, input_queue: Queue, output_queue: Queue, time_window: int):
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.time_window = time_window
        
        # State: Dictionary to store active flows {flow_key: flow_stats}
        self.active_flows = {} 
        self._stop_event = threading.Event()
        
        # Separate thread for periodic flow management (timeouts, flushing)
        self.flusher_thread = threading.Thread(target=self._flow_flusher, daemon=True)
        print("[Analyzer] Initialized. Flow aggregation window:", time_window, "seconds.")

    from typing import Optional

    def _get_flow_key(self, packet) -> Optional[str]:
        """
        Creates a unique, directional 5-tuple key for a network flow.
        (Src IP, Dst IP, Src Port, Dst Port, Protocol)
        """
        # Ensure it's an IP packet and has a transport layer
        if not (IP in packet and (TCP in packet or UDP in packet)):
            return None
        
        ip_layer = packet[IP]
        transport_layer = packet[TCP] if TCP in packet else (packet[UDP] if UDP in packet else None)
        
        if not transport_layer:
            return None

        # Sort the (IP, Port) pairs to ensure flow key is non-directional (a better practice
        # for training based on standard flow metrics, but a directional key is also valid).
        src_info = (ip_layer.src, transport_layer.sport)
        dst_info = (ip_layer.dst, transport_layer.dport)
        
        # Canonical flow key (Source/Destination is arbitrary for the key, for simplicity)
        key_parts = (
            ip_layer.src, 
            ip_layer.dst, 
            transport_layer.sport, 
            transport_layer.dport, 
            ip_layer.proto
        )
        return str(key_parts)


    def _update_flow_stats(self, packet):
        """
        Processes a single packet and updates the state of its corresponding flow.
        """
        flow_key = self._get_flow_key(packet)
        if not flow_key:
            return

        current_time = time.time()
        packet_size = len(packet)

        # Initialize flow if it's new
        if flow_key not in self.active_flows:
            self.active_flows[flow_key] = {
                'start_time': current_time,
                'last_time': current_time,
                'packet_count': 0,
                'byte_count': 0,
                'max_pkt_size': 0,
                'sum_pkt_size': 0,
                'is_tcp_fin_flag': False,
            }

        stats = self.active_flows[flow_key]
        
        # Update statistics
        stats['last_time'] = current_time
        stats['packet_count'] += 1
        stats['byte_count'] += packet_size
        stats['max_pkt_size'] = max(stats['max_pkt_size'], packet_size)
        stats['sum_pkt_size'] += packet_size

        # Check for TCP FIN flag (indicates a graceful flow termination)
        if TCP in packet and packet[TCP].flags.has('F'):
             stats['is_tcp_fin_flag'] = True
             
        # Add a reference back to the flow key for the enforcer
        stats['flow_id'] = flow_key


    def _extract_and_normalize_features(self, stats: dict) -> tuple:
        """
        Calculates the final feature vector from the raw statistics.
        NOTE: This is a placeholder for your full feature set.
        """
        duration = stats['last_time'] - stats['start_time']
        
        if stats['packet_count'] > 0:
            avg_pkt_size = stats['sum_pkt_size'] / stats['packet_count']
        else:
            avg_pkt_size = 0
            
        # Create the feature vector (must match the order of your model training!)
        feature_vector = np.array([
            stats['packet_count'], 
            stats['byte_count'], 
            duration, 
            stats['max_pkt_size'],
            avg_pkt_size,
            int(stats['is_tcp_fin_flag']),
        ])
        
        # The flow_id is used by the enforcer for logging/blocking
        flow_id = stats['flow_id']
        
        # Reshape for a single sample prediction (required by most ML models)
        return feature_vector.reshape(1, -1), flow_id


    def _flow_flusher(self):
        """
        Runs in a separate thread to periodically check for completed or timed-out flows
        and pushes their final features to the output queue.
        """
        print(f"[Analyzer] Flusher thread started. Checking flows every {self.time_window}s.")
        
        while not self._stop_event.is_set():
            time.sleep(self.time_window)
            if self._stop_event.is_set():
                break

            flows_to_flush = []
            current_time = time.time()

            for key, stats in list(self.active_flows.items()):
                # Condition 1: Flow Duration Timeout (e.g., 5 seconds)
                is_timeout = (current_time - stats['start_time']) >= self.time_window
                
                # Condition 2: TCP FIN flag set (graceful closure)
                is_closed = stats['is_tcp_fin_flag']
                
                # Condition 3: Idle Timeout (no activity for a while, e.g., 2*time_window)
                is_idle_timeout = (current_time - stats['last_time']) >= (self.time_window * 2)

                if is_timeout or is_closed or is_idle_timeout:
                    flows_to_flush.append(key)
            
            # Process and flush the ready flows
            for key in flows_to_flush:
                stats = self.active_flows.pop(key)
                feature_vector, flow_id = self._extract_and_normalize_features(stats)
                
                # Push the feature vector to the output queue
                self.output_queue.put((feature_vector, flow_id))
                
            # print(f"[Analyzer] Flushed {len(flows_to_flush)} flows. Active flows: {len(self.active_flows)}")


    def start_analysis(self):
        """
        Main loop to start the analysis and flow flusher thread.
        """
        self.flusher_thread.start()
        
        print("[Analyzer] Main analysis loop started.")
        while not self._stop_event.is_set():
            try:
                # Get the raw packet from the Sniffer queue (with a short timeout)
                packet = self.input_queue.get(timeout=0.1) 
                self._update_flow_stats(packet)
                self.input_queue.task_done() # Signal that the packet is processed
                
            except Empty:
                # If the queue is empty, the loop continues and checks the stop event
                continue
            except Exception as e:
                print(f"[Analyzer ERROR] Failed to process packet: {e}")
                
        print("[Analyzer] Analysis loop finished.")


    def stop_analysis(self):
        """
        Sets the stop event and waits for the flusher thread to join.
        """
        print("[Analyzer] Signal received to stop.")
        self._stop_event.set()
        if self.flusher_thread.is_alive():
            self.flusher_thread.join(timeout=self.time_window * 2)