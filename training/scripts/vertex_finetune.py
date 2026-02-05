#!/usr/bin/env python3
"""
Fine-tune Gemini on Vertex AI using the prepared training data.
"""

import json
import time
import os
from pathlib import Path
from datetime import datetime

try:
    import vertexai
    from vertexai.tuning import sft
    from google.cloud import storage
except ImportError:
    print("Installing required packages...")
    os.system("pip install google-cloud-aiplatform google-cloud-storage -q")
    import vertexai
    from vertexai.tuning import sft
    from google.cloud import storage

TRAIN_FILE = Path("/root/resurface/training/data/train.jsonl")
PROJECT_ID = None  # Set via argument
LOCATION = "us-central1"  # Vertex AI location
BUCKET_NAME = None  # Set via argument

def upload_to_gcs(local_path: Path, bucket_name: str, blob_name: str) -> str:
    """Upload training data to Google Cloud Storage."""
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)
    
    blob.upload_from_filename(str(local_path))
    gcs_uri = f"gs://{bucket_name}/{blob_name}"
    print(f"Uploaded {local_path} to {gcs_uri}")
    return gcs_uri

def start_tuning_job(
    project_id: str,
    location: str,
    training_data_uri: str,
    model_display_name: str,
    base_model: str = "gemini-1.5-flash-002",
    epochs: int = 3,
    learning_rate_multiplier: float = 1.0
):
    """Start a Vertex AI supervised fine-tuning job."""
    
    vertexai.init(project=project_id, location=location)
    
    print(f"\n{'='*60}")
    print(f"Starting Fine-Tuning Job")
    print(f"{'='*60}")
    print(f"Project: {project_id}")
    print(f"Location: {location}")
    print(f"Base Model: {base_model}")
    print(f"Training Data: {training_data_uri}")
    print(f"Display Name: {model_display_name}")
    print(f"Epochs: {epochs}")
    print(f"Learning Rate Multiplier: {learning_rate_multiplier}")
    print(f"{'='*60}\n")
    
    # Start the tuning job
    sft_tuning_job = sft.train(
        source_model=base_model,
        train_dataset=training_data_uri,
        tuned_model_display_name=model_display_name,
        epochs=epochs,
        learning_rate_multiplier=learning_rate_multiplier,
    )
    
    print(f"Tuning job started!")
    print(f"Job name: {sft_tuning_job.name}")
    print(f"\nMonitor at: https://console.cloud.google.com/vertex-ai/training/training-pipelines?project={project_id}")
    
    # Wait for completion (optional - can also monitor in console)
    print("\nWaiting for job to complete (this may take 30-60 minutes)...")
    print("You can also monitor progress in the Google Cloud Console.\n")
    
    while not sft_tuning_job.has_ended:
        time.sleep(60)
        sft_tuning_job.refresh()
        print(f"  Status: {sft_tuning_job.state}")
    
    if sft_tuning_job.has_succeeded:
        print(f"\n✅ Fine-tuning completed successfully!")
        print(f"Tuned model endpoint: {sft_tuning_job.tuned_model_endpoint_name}")
        print(f"Tuned model name: {sft_tuning_job.tuned_model_name}")
        
        # Save the model info
        model_info = {
            "job_name": sft_tuning_job.name,
            "base_model": base_model,
            "tuned_model_name": sft_tuning_job.tuned_model_name,
            "tuned_model_endpoint": sft_tuning_job.tuned_model_endpoint_name,
            "training_data": training_data_uri,
            "epochs": epochs,
            "completed_at": datetime.now().isoformat()
        }
        
        model_info_file = Path("/root/resurface/training/tuned_model_info.json")
        with open(model_info_file, 'w') as f:
            json.dump(model_info, f, indent=2)
        print(f"\nModel info saved to: {model_info_file}")
        
        return sft_tuning_job
    else:
        print(f"\n❌ Fine-tuning failed!")
        print(f"Error: {sft_tuning_job.error}")
        return None

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Fine-tune Gemini on Vertex AI")
    parser.add_argument("--project", required=True, help="GCP Project ID")
    parser.add_argument("--bucket", required=True, help="GCS bucket for training data")
    parser.add_argument("--model", default="gemini-1.5-flash-002", 
                       help="Base model (gemini-1.5-flash-002 or gemini-1.5-pro-002)")
    parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs")
    parser.add_argument("--lr-multiplier", type=float, default=1.0, 
                       help="Learning rate multiplier")
    parser.add_argument("--name", default=None, help="Display name for tuned model")
    parser.add_argument("--location", default="us-central1", help="Vertex AI location")
    
    args = parser.parse_args()
    
    # Set default name
    if args.name is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        args.name = f"resurface-vuln-hunter-{timestamp}"
    
    # Upload training data to GCS
    blob_name = f"resurface/training/{datetime.now().strftime('%Y%m%d')}/train.jsonl"
    training_data_uri = upload_to_gcs(TRAIN_FILE, args.bucket, blob_name)
    
    # Start fine-tuning
    start_tuning_job(
        project_id=args.project,
        location=args.location,
        training_data_uri=training_data_uri,
        model_display_name=args.name,
        base_model=args.model,
        epochs=args.epochs,
        learning_rate_multiplier=args.lr_multiplier
    )

if __name__ == "__main__":
    main()
