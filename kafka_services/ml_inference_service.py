from kafka import KafkaConsumer, KafkaProducer
import json
import numpy as np
import pandas as pd
from datetime import datetime
import logging
import pickle
import joblib
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkGuardMLInference:
    def __init__(self, bootstrap_servers=['localhost:9092']):
        self.consumer = KafkaConsumer(
            'feature-extraction-results',
            bootstrap_servers=bootstrap_servers,
            group_id='ml-inference-group',
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            auto_offset_reset='latest',
            enable_auto_commit=False
        )
        
        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda x: json.dumps(x).encode('utf-8'),
            key_serializer=lambda x: x.encode('utf-8')
        )
        
        # Your EXACT 30 features from NetworkGuard dataset
        self.feature_names = [
            'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
            'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
            'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
            'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
            'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
            'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
            'Statistical_report'
        ]
        
        # Load your REAL trained model
        self.model = self.load_your_trained_model()
        
        logger.info("🧠 NetworkGuard ML Inference Service initialized with your trained model!")
    
    def load_your_trained_model(self):
        """Load your trained model from final_model/model.pkl"""
        model_path = 'final_model/model.pkl'
        
        try:
            # Try loading with joblib first
            model = joblib.load(model_path)
            logger.info(f"✅ Loaded YOUR trained model from: {model_path} (joblib)")
            return model
        except:
            try:
                # Try loading with pickle
                with open(model_path, 'rb') as f:
                    model = pickle.load(f)
                logger.info(f"✅ Loaded YOUR trained model from: {model_path} (pickle)")
                return model
            except Exception as e:
                logger.error(f"❌ Failed to load model from {model_path}: {e}")
                logger.error("Make sure your model file exists at final_model/model.pkl")
                return None
    
    def predict_with_your_model(self, features):
        """Make prediction using YOUR trained NetworkGuard model"""
        try:
            if self.model is not None:
                # Prepare feature vector in the correct order
                feature_vector = self.prepare_feature_vector(features)
                
                # Make prediction with YOUR model
                prediction = self.model.predict(feature_vector)[0]
                
                # Get prediction probability if available
                if hasattr(self.model, 'predict_proba'):
                    probabilities = self.model.predict_proba(feature_vector)[0]
                    confidence = float(max(probabilities))
                    # Risk score based on phishing probability
                    phishing_prob = probabilities[1] if len(probabilities) > 1 else confidence
                    risk_score = float(phishing_prob * 100)
                else:
                    confidence = 0.85  # Default confidence
                    risk_score = float(confidence * 100 if prediction == 1 else (1-confidence) * 100)
                
                return {
                    'prediction': 'phishing' if prediction == 1 else 'legitimate',
                    'confidence': confidence,
                    'risk_score': risk_score,
                    'model_type': 'your_trained_networkguard_model'
                }
            else:
                # Fallback to rule-based if model loading failed
                return self.networkguard_rule_based_fallback(features)
                
        except Exception as e:
            logger.error(f"Prediction error with your model: {e}")
            return self.networkguard_rule_based_fallback(features)
    
    def prepare_feature_vector(self, features):
        """Convert features dict to numpy array in the exact order your model expects"""
        vector = []
        for feature_name in self.feature_names:
            value = features.get(feature_name, 0)
            vector.append(float(value))
        
        # Convert to numpy array with shape (1, 30) for single prediction
        return np.array(vector).reshape(1, -1)
    
    def networkguard_rule_based_fallback(self, features):
        """Fallback rule-based classifier if model fails"""
        risk_score = 0
        
        # Your NetworkGuard feature-based rules
        if features.get('having_IP_Address', -1) == 1: risk_score += 30
        if features.get('URL_Length', -1) == 1: risk_score += 15
        if features.get('Shortining_Service', -1) == 1: risk_score += 20
        if features.get('having_At_Symbol', -1) == 1: risk_score += 25
        if features.get('SSLfinal_State', -1) == 1: risk_score += 20
        if features.get('having_Sub_Domain', -1) == 1: risk_score += 15
        if features.get('HTTPS_token', -1) == 1: risk_score += 25
        if features.get('age_of_domain', -1) == 1: risk_score += 20
        if features.get('DNSRecord', -1) == 1: risk_score += 30
        
        is_phishing = risk_score > 60
        confidence = min(risk_score / 100.0, 0.95)
        
        return {
            'prediction': 'phishing' if is_phishing else 'legitimate',
            'confidence': confidence,
            'risk_score': float(risk_score),
            'model_type': 'networkguard_rules_fallback'
        }
    
    def process_messages(self):
        """Process feature extraction results with YOUR trained model"""
        logger.info("🚀 Starting NetworkGuard ML inference with YOUR trained model...")
        
        if self.model is not None:
            logger.info("✅ Using YOUR trained model for predictions!")
        else:
            logger.warning("⚠️  Using rule-based fallback (model loading failed)")
        
        try:
            for message in self.consumer:
                data = message.value
                logger.info(f"🔍 Analyzing with YOUR model: {data['url']}")
                
                # Make prediction using YOUR trained model
                prediction = self.predict_with_your_model(data['features'])
                
                # Create result message
                result = {
                    'url': data['url'],
                    'id': data['id'],
                    'features': data['features'],
                    'prediction': prediction,
                    'timestamp': datetime.now().isoformat(),
                    'model_version': 'NetworkGuard-YourModel-v1.0',
                    'features_used': len(self.feature_names)
                }
                
                # Send prediction to Kafka
                self.producer.send('model-predictions', value=result, key=data['id'])
                
                # Generate threat alerts for phishing detections
                if (prediction['prediction'] == 'phishing' and 
                    prediction['confidence'] > 0.6):
                    
                    alert = {
                        'alert_type': 'networkguard_trained_model_phishing_detected',
                        'url': data['url'],
                        'risk_score': prediction['risk_score'],
                        'confidence': prediction['confidence'],
                        'model_type': prediction['model_type'],
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'high' if prediction['confidence'] > 0.8 else 'medium',
                        'features_count': len(data['features'])
                    }
                    
                    self.producer.send('threat-alerts', value=alert, key=data['id'])
                    logger.warning(f"🚨 PHISHING DETECTED: {data['url']}")
                    logger.warning(f"   Risk Score: {prediction['risk_score']:.1f}%")
                    logger.warning(f"   Confidence: {prediction['confidence']:.3f}")
                    logger.warning(f"   Model: {prediction['model_type']}")
                else:
                    logger.info(f"✅ LEGITIMATE: {data['url']} (Risk: {prediction['risk_score']:.1f}%)")
                
                # Commit message
                self.consumer.commit()
                
        except KeyboardInterrupt:
            logger.info("🛑 Stopping NetworkGuard ML inference service...")
        except Exception as e:
            logger.error(f"❌ Error in processing: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Clean up connections"""
        self.consumer.close()
        self.producer.close()
        logger.info("NetworkGuard ML Inference Service stopped")

if __name__ == "__main__":
    service = NetworkGuardMLInference()
    
    print("🛡️  NetworkGuard ML Inference Service with YOUR Trained Model!")
    print("📍 Model Location: final_model/model.pkl")
    print("🎯 Features: 30 NetworkGuard features")
    print("🚀 Ready to detect phishing with your trained model!")
    print("\nPress Ctrl+C to stop.\n")
    
    service.process_messages()
