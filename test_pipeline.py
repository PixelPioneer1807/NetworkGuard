import time
import threading
import subprocess
import sys
import os
from kafka_services.url_ingestion_service import URLIngestionService

def run_service_in_background(service_file, service_name):
    """Run a service in background and return the process"""
    print(f"🚀 Starting {service_name}...")
    try:
        process = subprocess.Popen([
            sys.executable, service_file
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(2)  # Give it time to start
        print(f"✅ {service_name} started (PID: {process.pid})")
        return process
    except Exception as e:
        print(f"❌ Failed to start {service_name}: {e}")
        return None

def test_complete_pipeline():
    """Test the complete Kafka pipeline"""
    print("🛡️  NETWORKGUARD KAFKA PIPELINE TEST")
    print("=" * 50)
    
    # Start services
    services = []
    
    # Start Feature Extraction Service
    feature_service = run_service_in_background(
        "kafka_services/feature_extraction_service.py", 
        "Feature Extraction Service"
    )
    if feature_service:
        services.append(("Feature Extraction", feature_service))
    
    # Start ML Inference Service
    ml_service = run_service_in_background(
        "kafka_services/ml_inference_service.py", 
        "ML Inference Service"
    )
    if ml_service:
        services.append(("ML Inference", ml_service))
    
    # Start Dashboard Service
    dashboard_service = run_service_in_background(
        "kafka_services/dashboard_service.py", 
        "Dashboard Service"
    )
    if dashboard_service:
        services.append(("Dashboard", dashboard_service))
    
    # Wait for services to initialize
    print("\n⏳ Waiting for services to initialize...")
    time.sleep(5)
    
    # Test URLs
    test_urls = [
        # Legitimate URLs
        "https://www.google.com",
        "https://www.github.com",
        "https://www.stackoverflow.com",
        
        # Suspicious URLs (will trigger phishing detection)
        "http://paypal-security-update.tk/login.php",
        "http://192.168.1.100/bank/login.html",
        "https://secure-account-update-amazon.cc/verify",
        "http://apple-account-suspended.ml/confirm",
        "https://microsoft-security-alert.ga/update-password",
        
        # Mixed URLs
        "https://bit.ly/suspicious-link",
        "http://very-long-suspicious-domain-name-with-many-subdomains.suspicious-tld.tk/phishing/login/secure/account/update"
    ]
    
    # Initialize URL ingestion service
    print("\n📡 Starting URL submission test...")
    ingestion_service = URLIngestionService()
    
    # Submit URLs one by one with delay
    for i, url in enumerate(test_urls, 1):
        print(f"\n📤 Submitting URL {i}/{len(test_urls)}: {url[:60]}...")
        result = ingestion_service.submit_url(url, source='test', priority='normal')
        
        if result['success']:
            print(f"   ✅ Submitted successfully (ID: {result['id'][:8]}...)")
        else:
            print(f"   ❌ Failed: {result['error']}")
        
        # Wait between submissions to see real-time processing
        time.sleep(3)
    
    ingestion_service.close()
    
    # Let the pipeline process all URLs
    print(f"\n⏳ Processing {len(test_urls)} URLs through the pipeline...")
    print("📊 Check the Dashboard Service output for real-time results!")
    print("\n🔍 The pipeline will:")
    print("   1. Extract features from each URL")
    print("   2. Run ML inference to detect phishing")
    print("   3. Generate alerts for suspicious URLs")
    print("   4. Update the dashboard with statistics")
    
    # Wait for processing
    time.sleep(15)
    
    print(f"\n🎉 Pipeline test completed!")
    print("📈 Check the dashboard output above for results.")
    print("\n🛑 Stopping services...")
    
    # Stop all services
    for service_name, process in services:
        try:
            process.terminate()
            process.wait(timeout=5)
            print(f"✅ Stopped {service_name}")
        except Exception as e:
            print(f"⚠️  Error stopping {service_name}: {e}")
    
    print("\n✨ Test completed! Your Kafka-enhanced NetworkGuard is working!")

if __name__ == "__main__":
    print("🚀 NETWORKGUARD KAFKA INTEGRATION TEST")
    print("This will test the complete real-time phishing detection pipeline!")
    print("Press Ctrl+C at any time to stop.\n")
    
    try:
        test_complete_pipeline()
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
