#!/usr/bin/env python3
"""
Training Script for Local Security Classifier
Run this to train and evaluate local models
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.local_classifier_trainer import SecurityClassifierTrainer
import json

def main():
    print("=== LOCAL SECURITY CLASSIFIER TRAINING ===\n")
    
    # Initialize trainer
    trainer = SecurityClassifierTrainer()
    
    # Step 1: Create dataset
    print("1. Creating sample security dataset...")
    df = trainer.create_sample_dataset()
    print(f"   Dataset created with {len(df)} samples")
    print(f"   Classes: {df['label'].value_counts().to_dict()}\n")
    
    # Step 2: Train models
    print("2. Training classification models...")
    results = trainer.train_models(df)
    
    # Step 3: Evaluate models
    print("3. Evaluating model performance...")
    evaluation = trainer.evaluate_models()
    
    print("\n=== MODEL PERFORMANCE ===")
    for name, eval_result in evaluation.items():
        if 'error' not in eval_result:
            print(f"\n{name.upper()}:")
            print(f"  Accuracy: {eval_result['accuracy']:.3f}")
            print(f"  Model Type: {eval_result['model_type']}")
            
            # Show per-class performance
            if 'classification_report' in eval_result:
                report = eval_result['classification_report']
                print("  Per-Class Performance:")
                for class_name in ['SQL_Injection', 'XSS', 'Normal']:
                    if class_name in report:
                        metrics = report[class_name]
                        print(f"    {class_name}: F1={metrics.get('f1-score', 0):.3f}")
    
    # Step 4: Save models
    print("\n4. Saving trained models...")
    trainer.save_models()
    
    # Step 5: Test with sample requests
    print("\n5. Testing with sample requests...")
    
    test_requests = [
        "SELECT * FROM users WHERE id=1 OR 1=1",
        "<script>alert('XSS')</script>",
        "GET /home normal browsing",
        "; cat /etc/passwd"
    ]
    
    for test_text in test_requests:
        result = trainer.predict(test_text, 'random_forest')
        print(f"\n  Input: {test_text}")
        print(f"  Prediction: {result['classification']} (confidence: {result['confidence']:.2f})")
    
    print("\n=== TRAINING COMPLETE ===")
    print("Models saved in 'models/' directory")
    print("Ready to use in production!")
    
    return evaluation

if __name__ == "__main__":
    evaluation = main()
