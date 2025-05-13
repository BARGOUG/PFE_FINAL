import joblib
import os

# Define absolute paths for the model, vectorizer, and report file
BASE_DIR = "/var/www/PFE_FINAL"
TFIDF_VECTORIZER_PATH = os.path.join(BASE_DIR, "BEST_MODEL", "bow_vectorizer.joblib")
MLP_MODEL_PATH = os.path.join(BASE_DIR, "BEST_MODEL", "mlp_model.joblib")
REPORT_FILE_PATH = os.path.join(BASE_DIR, "report_results", "report.txt")

# Load the TF-IDF vectorizer
tfidf = joblib.load(TFIDF_VECTORIZER_PATH)

# Define the cleaning function (same as during training)
def clean_api_calls(api_sequence):
    cleaned_sequence = " ".join([call.split('.')[-1] for call in api_sequence.split()])
    return cleaned_sequence

# Function to make predictions
def predict_malware(api_calls, threshold=0.5):
    """
    Predicts whether the given API call sequence is malware or goodware using all trained models.
    
    Parameters:
        api_calls (str): A string of API calls separated by spaces.
        threshold (float): Decision threshold for classification.
    
    Returns:
        dict: A dictionary containing predictions from all models.
    """
    # Clean the input
    cleaned_calls = clean_api_calls(api_calls)
    
    # Transform the input using the TF-IDF vectorizer
    X_input = tfidf.transform([cleaned_calls])
    
    # Load the MLP model
    model = joblib.load(MLP_MODEL_PATH)
    
    # Make predictions
    probability = model.predict_proba(X_input)[0][1]  # Probability of being malware
    prediction = "Malware" if probability >= threshold else "Goodware"
    
    # Store results
    return {
        "predicted_label": prediction,
        "malware_probability": float(probability)
    }

# Example usage
if __name__ == "__main__":
    # Read API calls from the report file
    try:
        with open(REPORT_FILE_PATH, "r", encoding="utf-8") as file:
            sample_api_calls = file.read().strip()  # Read and remove leading/trailing whitespace
    except FileNotFoundError:
        print(f"Error: The file '{REPORT_FILE_PATH}' was not found.")
        exit()
    except Exception as e:
        print(f"Error reading the file: {e}")
        exit()

    # Remove newlines and extra spaces
    sample_api_calls = " ".join(sample_api_calls.split())
    
    # Predict with a custom threshold (e.g., 0.5)
    results = predict_malware(sample_api_calls, threshold=0.5)
    
    # Print results
    print("\nPredictions:")
    print(f"Prediction: {results['predicted_label']}")
    print(f"Malware Probability: {results['malware_probability']:.4f}")
