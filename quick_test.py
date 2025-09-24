from kafka_services.url_ingestion_service import URLIngestionService
import time

# Test URLs
test_urls = [
    "https://www.amazon.com",  # Should be LEGITIMATE
    "http://paypal-security-update.tk/login.php",  # Should be PHISHING
    "http://192.168.1.100/bank/login.html", #phishing
    "https://www.kdfdbfiud.com"# Should be PHISHING
]

service = URLIngestionService()

for url in test_urls:
    print(f"📤 Sending: {url}")
    service.submit_url(url)
    time.sleep(2)  # Wait 2 seconds between submissions

service.close()
print("✅ Done! Check the other windows for processing results!")
