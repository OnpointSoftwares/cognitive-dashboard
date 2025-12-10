#!/usr/bin/env python3
"""
Setup script for Gemini API integration
Helps users configure Google Gemini API key for enhanced threat detection
"""
import os
import sys
from pathlib import Path

def setup_gemini():
    """Setup Gemini API configuration"""
    print("=== Cognitive Security Dashboard - Gemini API Setup ===\n")
    
    # Check if .env file exists
    env_file = Path(".env")
    env_example = Path(".env")
    
    if not env_example.exists():
        print("❌ Error: .env.example file not found!")
        print("Please ensure you're running this from the backend directory.")
        return False
    
    # Read example file
    with open(env_example, 'r') as f:
        env_content = f.read()
    
    print("📋 This script will help you configure Google Gemini API for enhanced threat detection.")
    print("🔗 Get your API key from: https://makersuite.google.com/app/apikey\n")
    
    # Get API key from user
    api_key = input("🔑 Enter your Gemini API key (or press Enter to skip): ").strip()
    
    if not api_key:
        print("⏭️  Gemini API setup skipped. System will use ML model only.")
        return True
    
    # Validate API key format (basic check)
    if not api_key.startswith(('AIza', 'AIzaSy')):
        print("⚠️  Warning: API key format looks unusual. Please verify it's correct.")
        confirm = input("Continue anyway? (y/N): ").strip().lower()
        if confirm != 'y':
            print("❌ Setup cancelled.")
            return False
    
    # Create .env file
    try:
        # Replace placeholder with actual key
        env_content = env_content.replace('your_gemini_api_key_here', api_key)
        
        with open(env_file, 'w') as f:
            f.write(env_content)
        
        print("✅ Success! .env file created with your Gemini API key.")
        print("🔒 Your API key is stored securely in .env file.")
        print("📝 Make sure .env is in your .gitignore file!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating .env file: {e}")
        return False

def test_gemini_connection():
    """Test Gemini API connection"""
    try:
        # Load environment variables from .env file
        from dotenv import load_dotenv
        load_dotenv()
        
        from app.gemini_ai_detector import GeminiAIDetector
        
        print("\n🧪 Testing Gemini API connection...")
        detector = GeminiAIDetector()
        
        if not detector.enabled:
            print("❌ Gemini API not configured. Please check your .env file.")
            return False
        
        # Test with a simple request
        test_request = {
            'method': 'GET',
            'uri': '/test',
            'source_ip': '127.0.0.1',
            'user_agent': 'Test-Agent/1.0',
            'body': '',
            'headers': {}
        }
        
        import asyncio
        result = asyncio.run(detector.analyze_with_gemini(test_request))
        
        if 'error' in result:
            print(f"❌ Gemini API test failed: {result['error']}")
            return False
        else:
            print("✅ Gemini API connection successful!")
            print(f"📊 Test classification: {result.get('classification', 'Unknown')}")
            print(f"🎯 Confidence: {result.get('confidence', 0.0):.2f}")
            return True
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure you have installed required dependencies:")
        print("pip install -r requirements.txt")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

def show_features():
    """Show Gemini integration features"""
    print("\n🚀 Gemini Integration Features:")
    print("   • Enhanced threat classification with LLM analysis")
    print("   • Detailed reasoning for threat detection")
    print("   • Specific threat indicators identification")
    print("   • Recommended security actions")
    print("   • Hybrid ML + AI approach for accuracy")
    print("   • Rate limiting and caching for efficiency")
    print("\n📊 Supported Threat Types:")
    print("   • SQL Injection")
    print("   • Cross-Site Scripting (XSS)")
    print("   • Command Injection")
    print("   • Path Traversal")
    print("   • DDoS Attacks")
    print("   • Brute Force Attacks")
    print("   • Bot/Scanner Activity")
    print("   • Normal/Legitimate Traffic")

def main():
    """Main setup function"""
    if len(sys.argv) > 1:
        if sys.argv[1] == '--test':
            test_gemini_connection()
        elif sys.argv[1] == '--features':
            show_features()
        elif sys.argv[1] == '--help':
            print("Usage: python setup_gemini.py [OPTION]")
            print("Options:")
            print("  (no args)  - Setup Gemini API key")
            print("  --test      - Test Gemini API connection")
            print("  --features  - Show Gemini integration features")
            print("  --help      - Show this help message")
        else:
            print(f"Unknown option: {sys.argv[1]}")
            print("Use --help for available options.")
    else:
        # Default behavior: setup
        success = setup_gemini()
        if success:
            print("\n🎉 Setup complete! You can now:")
            print("   1. Start the system: python run_dfd_system.py")
            print("   2. Test the connection: python setup_gemini.py --test")
            print("   3. View features: python setup_gemini.py --features")

if __name__ == "__main__":
    main()
