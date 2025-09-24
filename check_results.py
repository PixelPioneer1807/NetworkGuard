from kafka import KafkaConsumer
import json
from datetime import datetime

def check_kafka_topics():
    """Check what data is in our Kafka topics"""
    
    topics_to_check = [
        'url-submissions',
        'feature-extraction-results', 
        'model-predictions',
        'threat-alerts'
    ]
    
    for topic in topics_to_check:
        print(f"\n📋 CHECKING TOPIC: {topic}")
        print("=" * 60)
        
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=['localhost:9092'],
                value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                auto_offset_reset='earliest',  # Read from beginning
                consumer_timeout_ms=5000  # 5 second timeout
            )
            
            message_count = 0
            for message in consumer:
                message_count += 1
                data = message.value
                
                if topic == 'url-submissions':
                    print(f"  {message_count}. URL: {data['url']}")
                    print(f"     Source: {data['source']}, Time: {data['timestamp']}")
                
                elif topic == 'feature-extraction-results':
                    print(f"  {message_count}. URL: {data['url']}")
                    print(f"     Features extracted: {len(data['features'])} features")
                    print(f"     Sample features: url_length={data['features'].get('url_length')}, has_https={data['features'].get('has_https')}")
                
                elif topic == 'model-predictions':
                    pred = data['prediction']
                    print(f"  {message_count}. URL: {data['url']}")
                    print(f"     PREDICTION: {pred['prediction']} (Risk: {pred['risk_score']:.1f}%, Confidence: {pred['confidence']:.2f})")
                
                elif topic == 'threat-alerts':
                    print(f"  {message_count}. 🚨 ALERT: {data['severity'].upper()}")
                    print(f"     URL: {data['url']}")
                    print(f"     Risk Score: {data['risk_score']:.1f}%")
            
            if message_count == 0:
                print("  ❌ No messages found in this topic")
            else:
                print(f"  ✅ Found {message_count} messages")
            
            consumer.close()
            
        except Exception as e:
            print(f"  ❌ Error reading topic {topic}: {e}")

def check_kafka_ui():
    """Instructions to check Kafka UI"""
    print("\n🌐 KAFKA UI VERIFICATION:")
    print("=" * 40)
    print("1. Open your browser to: http://localhost:8080")
    print("2. Click on 'Topics' in the left menu")
    print("3. You should see these topics:")
    print("   - url-submissions")
    print("   - feature-extraction-results")
    print("   - model-predictions") 
    print("   - threat-alerts")
    print("4. Click on any topic to see the messages")
    print("5. Click 'Messages' tab to see actual data")

if __name__ == "__main__":
    print("🔍 NETWORKGUARD KAFKA VERIFICATION")
    print("Checking what data was processed through the pipeline...")
    
    check_kafka_topics()
    check_kafka_ui()
    
    print(f"\n✅ Verification completed at {datetime.now().strftime('%H:%M:%S')}")
