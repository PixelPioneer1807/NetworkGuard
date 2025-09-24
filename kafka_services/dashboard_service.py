from kafka import KafkaConsumer
import json
import threading
import time
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DashboardService:
    def __init__(self, bootstrap_servers=['localhost:9092']):
        self.consumer = KafkaConsumer(
            'model-predictions',
            'threat-alerts',
            bootstrap_servers=bootstrap_servers,
            group_id='dashboard-group',
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            auto_offset_reset='latest'
        )
        
        # Statistics
        self.stats = {
            'total_urls_processed': 0,
            'phishing_detected': 0,
            'legitimate_detected': 0,
            'alerts_sent': 0,
            'avg_risk_score': 0.0,
            'last_updated': datetime.now().isoformat()
        }
        
        self.recent_predictions = []
        self.recent_alerts = []
        
        logger.info("Dashboard Service initialized")
    
    def process_messages(self):
        """Process Kafka messages and update dashboard"""
        logger.info("Dashboard Service started - monitoring predictions and alerts...")
        
        try:
            for message in self.consumer:
                if message.topic == 'model-predictions':
                    self.handle_prediction(message.value)
                elif message.topic == 'threat-alerts':
                    self.handle_alert(message.value)
                
                # Print dashboard every 5 predictions
                if self.stats['total_urls_processed'] % 5 == 0:
                    self.print_dashboard()
                    
        except KeyboardInterrupt:
            logger.info("Dashboard Service stopping...")
        except Exception as e:
            logger.error(f"Error in dashboard service: {e}")
        finally:
            self.consumer.close()
    
    def handle_prediction(self, data):
        """Handle new prediction results"""
        self.stats['total_urls_processed'] += 1
        
        if data['prediction']['prediction'] == 'phishing':
            self.stats['phishing_detected'] += 1
        else:
            self.stats['legitimate_detected'] += 1
        
        # Update average risk score
        risk_score = data['prediction']['risk_score']
        current_avg = self.stats['avg_risk_score']
        total_urls = self.stats['total_urls_processed']
        self.stats['avg_risk_score'] = ((current_avg * (total_urls - 1)) + risk_score) / total_urls
        
        self.stats['last_updated'] = datetime.now().isoformat()
        
        # Keep recent predictions (last 10)
        prediction_summary = {
            'url': data['url'],
            'prediction': data['prediction']['prediction'],
            'risk_score': data['prediction']['risk_score'],
            'confidence': data['prediction']['confidence'],
            'timestamp': data['timestamp']
        }
        
        self.recent_predictions.append(prediction_summary)
        if len(self.recent_predictions) > 10:
            self.recent_predictions.pop(0)
    
    def handle_alert(self, data):
        """Handle new alerts"""
        self.stats['alerts_sent'] += 1
        self.stats['last_updated'] = datetime.now().isoformat()
        
        # Keep recent alerts (last 5)
        alert_summary = {
            'url': data['url'],
            'severity': data['severity'],
            'risk_score': data['risk_score'],
            'timestamp': data['timestamp']
        }
        
        self.recent_alerts.append(alert_summary)
        if len(self.recent_alerts) > 5:
            self.recent_alerts.pop(0)
        
        # Print immediate alert
        print(f"\n🚨 NEW ALERT: {data['severity'].upper()} - {data['url']}")
        print(f"   Risk Score: {data['risk_score']:.1f}%")
        print("-" * 60)
    
    def print_dashboard(self):
        """Print current dashboard state"""
        print("\n" + "=" * 80)
        print("🛡️  NETWORKGUARD REAL-TIME PHISHING DETECTION DASHBOARD")
        print("=" * 80)
        
        # Statistics
        print(f"📊 STATISTICS:")
        print(f"   Total URLs Processed: {self.stats['total_urls_processed']}")
        print(f"   Phishing Detected: {self.stats['phishing_detected']}")
        print(f"   Legitimate URLs: {self.stats['legitimate_detected']}")
        print(f"   Alerts Sent: {self.stats['alerts_sent']}")
        print(f"   Average Risk Score: {self.stats['avg_risk_score']:.1f}%")
        
        # Detection rate
        if self.stats['total_urls_processed'] > 0:
            phishing_rate = (self.stats['phishing_detected'] / self.stats['total_urls_processed']) * 100
            print(f"   Phishing Detection Rate: {phishing_rate:.1f}%")
        
        print(f"   Last Updated: {self.stats['last_updated']}")
        
        # Recent predictions
        if self.recent_predictions:
            print(f"\n🔍 RECENT PREDICTIONS:")
            for pred in self.recent_predictions[-5:]:  # Show last 5
                status_icon = "🚨" if pred['prediction'] == 'phishing' else "✅"
                print(f"   {status_icon} {pred['url'][:50]}... ")
                print(f"      → {pred['prediction'].upper()} (Risk: {pred['risk_score']:.1f}%, Confidence: {pred['confidence']:.2f})")
        
        # Recent alerts
        if self.recent_alerts:
            print(f"\n⚠️  RECENT ALERTS:")
            for alert in self.recent_alerts[-3:]:  # Show last 3
                severity_icon = "🔴" if alert['severity'] == 'high' else "🟡"
                print(f"   {severity_icon} {alert['severity'].upper()}: {alert['url'][:50]}...")
                print(f"      → Risk Score: {alert['risk_score']:.1f}%")
        
        print("=" * 80)
        print(f"⏰ Updated at: {datetime.now().strftime('%H:%M:%S')}")
        print("=" * 80)

if __name__ == "__main__":
    dashboard = DashboardService()
    
    print("🛡️  NetworkGuard Dashboard Service Starting...")
    print("This will show real-time phishing detection results!")
    print("Press Ctrl+C to stop.\n")
    
    dashboard.process_messages()
