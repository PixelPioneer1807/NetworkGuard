from kafka import KafkaProducer, KafkaConsumer
from kafka.admin import KafkaAdminClient, NewTopic
import json
import time

# Test Kafka connection
def test_kafka():
    try:
        # Create admin client
        admin = KafkaAdminClient(bootstrap_servers=['localhost:9092'])
        
        # Create test topics
        topics = [
            NewTopic("url-submissions", num_partitions=3, replication_factor=1),
            NewTopic("test-topic", num_partitions=1, replication_factor=1)
        ]
        
        # Create topics
        admin.create_topics(topics)
        print("✅ Topics created successfully!")
        
        # Test producer
        producer = KafkaProducer(
            bootstrap_servers=['localhost:9092'],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )
        
        producer.send('test-topic', {'message': 'Hello Kafka!'})
        producer.flush()
        print("✅ Message sent successfully!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    test_kafka()
