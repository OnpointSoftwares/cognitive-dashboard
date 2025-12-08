#!/usr/bin/env python3
"""
Startup script for DFD-compliant Cognitive Security System
Usage: python run_dfd_system.py
"""
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.main import CognitiveSecuritySystem

if __name__ == "__main__":
    print("Starting Cognitive Security System - DFD Architecture")
    print("=" * 60)
    
    system = CognitiveSecuritySystem()
    system.run()
