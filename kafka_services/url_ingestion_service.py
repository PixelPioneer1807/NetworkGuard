from kafka import KafkaProducer
import json
import time
from datetime import datetime
import hashlib
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class URLIngestionService:
    def __init__(self, bootstrap_servers=['localhost:9092']):
        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda x: json.dumps(x).encode('utf-8'),
            key_serializer=lambda x: x.encode('utf-8'),
            batch_size=16384,
            linger_ms=10,
            compression_type='gzip',
            acks='all'
        )
        logger.info("URL Ingestion Service initialized")
    
    def submit_url(self, url, source='manual', priority='normal'):
        """Submit URL for phishing analysis"""
        try:
            url_data = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'source': source,
                'priority': priority,
                'id': hashlib.md5(url.encode()).hexdigest()
            }
            
            # Use URL hash as key for consistent partitioning
            key = url_data['id']
            
            future = self.producer.send('url-submissions', value=url_data, key=key)
            self.producer.flush()
            
            logger.info(f"URL submitted: {url}")
            return {'success': True, 'id': key}
            
        except Exception as e:
            logger.error(f"Error submitting URL {url}: {e}")
            return {'success': False, 'error': str(e)}
    
    def submit_bulk_urls(self, urls):
        """Submit multiple URLs efficiently"""
        results = []
        for url in urls:
            result = self.submit_url(url)
            results.append(result)
        return results
    
    def close(self):
        """Close producer connection"""
        self.producer.close()

# Test function
def test_ingestion():
    service = URLIngestionService()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "http://suspicious-site.tk/login.php",
        "https://paypal-security-update.com/verify"
    ]
    
    for url in test_urls:
        result = service.submit_url(url)
        print(f"Submitted {url}: {result}")
    
    service.close()

if __name__ == "__main__":
    test_ingestion()
