# traffic_sniffer.py (Comprehensive Version)

import threading
import ctypes
import os
import time
from queue import Queue, Empty

# ===================================================================
# CTYPE DEFINITIONS FOR C++ INTERFACE
# ===================================================================

# Define a simple C structure that the C++ engine will fill.
class C_PacketData(ctypes.Structure):
    """Represents a structured data unit passed from C++ to Python."""
    _fields_ = [
        ("timestamp", ctypes.c_double),
        ("length", ctypes.c_uint),
        ("flow_hash", ctypes.c_uint),
        ("is_alert", ctypes.c_bool),
    ]

# Define the constants for the shared buffer size
MAX_BUFFER_SLOTS = 1024  # Max number of C_PacketData structs in the buffer

# Define the C function signatures for the full control logic
_start_capture = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p)
_stop_capture = ctypes.CFUNCTYPE(ctypes.c_int) # Function to signal C++ engine to stop
_get_next_read_index = ctypes.CFUNCTYPE(ctypes.c_int) # Function to get index of new data

# The expected path of the compiled shared library inside the Docker container
LIB_PATH = "/usr/local/lib/libsniffer.so" 

# ===================================================================
# THE PYTHON WRAPPER CLASS
# ===================================================================

class PacketSniffer:
    """
    Python wrapper that uses ctypes to call a high-performance C++ library
    and manages the shared memory buffer for data transfer.
    """
    def __init__(self, interface: str, output_queue: Queue):
        self.interface = interface
        self.output_queue = output_queue
        self._stop_event = threading.Event()
        self.c_library = None
        self._load_c_library()
        
        # Shared memory buffer and read index tracking
        # We use a C-style array here as the conceptual shared memory buffer
        self.shared_buffer = (C_PacketData * MAX_BUFFER_SLOTS)()
        self.last_read_index = 0
        
        # Thread for reading data from the C++ shared memory buffer
        self.reading_thread = threading.Thread(target=self._read_and_process_buffer, daemon=True)


    def _load_c_library(self):
        """Loads the compiled C++ shared library and maps functions."""
        if not os.path.exists(LIB_PATH):
            raise FileNotFoundError(f"C++ shared library not found at: {LIB_PATH}")
            
        try:
            self.c_library = ctypes.CDLL(LIB_PATH)
            
            # 1. Map start_capture_engine function
            self.c_library.start_capture_engine.argtypes = [ctypes.c_char_p, ctypes.POINTER(C_PacketData)]
            self.c_library.start_capture_engine.restype = ctypes.c_int
            
            # 2. Map stop_capture_engine function
            self.c_library.stop_capture_engine.argtypes = []
            self.c_library.stop_capture_engine.restype = ctypes.c_int
            
            # 3. Map function to get the current write index from C++
            self.c_library.get_write_index.argtypes = []
            self.c_library.get_write_index.restype = ctypes.c_int
            
            print("[Sniffer] C++ library and functions loaded successfully.")
            
        except Exception as e:
            print(f"[Sniffer ERROR] Could not load C++ library: {e}")
            raise

    def _read_and_process_buffer(self):
        """
        Runs in a separate Python thread. 
        Continuously checks the C++ shared buffer for new data and pushes it to the Queue.
        """
        print("[Sniffer Reader] Started monitoring C++ shared buffer.")
        while not self._stop_event.is_set():
            try:
                # Get the current write position from the C++ engine
                if self.c_library is None:
                    print("[Sniffer Reader ERROR] C++ library not loaded.")
                    time.sleep(1)
                    continue
                current_write_index = self.c_library.get_write_index()
                
                # Check for new data written since the last read
                while self.last_read_index != current_write_index:
                    # Read the new data slot
                    data_slot = self.shared_buffer[self.last_read_index]
                    
                    # Convert the C structure data into a Python dictionary or tuple
                    processed_data = (
                        data_slot.timestamp,
                        data_slot.length,
                        data_slot.flow_hash,
                        data_slot.is_alert
                    )
                    
                    # Push the processed data to the Flow Analyzer queue
                    self.output_queue.put(processed_data)
                    
                    # Move to the next slot (wrap around at the buffer end)
                    self.last_read_index = (self.last_read_index + 1) % MAX_BUFFER_SLOTS
                    
                # Small pause to avoid busy-waiting and consuming excessive CPU
                time.sleep(0.001) 
                
            except Exception as e:
                print(f"[Sniffer Reader ERROR] Failed to read buffer: {e}")
                time.sleep(1) # Sleep longer on error

        print("[Sniffer Reader] Stopped.")


    def start_sniffing(self):
        """
        Starts the Python buffer reader and the C++ capture engine in the background.
        """
        # Start the Python thread that reads the C++ buffer
        self.reading_thread.start()
        
        print("[Sniffer] Launching high-speed C++ capture engine...")
        
        interface_bytes = self.interface.encode('utf-8')
        
        # Call the C++ function, passing the C buffer array (pointer)
        # The C++ function is expected to run in its own thread/loop and manage the buffer
        if self.c_library is None:
            print("[Sniffer ERROR] C++ library is not loaded. Cannot start capture engine.")
            return

        result = self.c_library.start_capture_engine(interface_bytes, self.shared_buffer)
        
        if result == 0:
            print("[Sniffer] C++ engine process terminated successfully.")
        else:
            print(f"[Sniffer ERROR] C++ engine returned error code: {result}")
        

    def stop_sniffing(self):
        """
        Signals the C++ engine to stop and waits for the reading thread to finish.
        """
        print("[Sniffer] Signal received to stop.")
        
        # 1. Signal the C++ engine to terminate its internal loop
        if self.c_library:
            self.c_library.stop_capture_engine() 
        
        # 2. Set the event to stop the Python reading thread
        self._stop_event.set()
        
        # 3. Wait for the reading thread to finish cleanly
        if self.reading_thread.is_alive():
            self.reading_thread.join(timeout=5)
            
        print("[Sniffer] Worker shutdown complete.")