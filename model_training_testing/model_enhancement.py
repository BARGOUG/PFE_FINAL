import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neural_network import MLPClassifier

# Paths to saved artifacts
TFIDF_VECTORIZER_PATH = "tfidf_vectorizer.pkl"
MLP_MODEL_PATH = "mlp_neural_network_model.pkl"

# Function to load existing artifacts (vectorizer and model)
def load_artifacts():
    tfidf = joblib.load(TFIDF_VECTORIZER_PATH)
    model = joblib.load(MLP_MODEL_PATH)
    return tfidf, model

# Function to preprocess API calls
def clean_api_calls(api_calls):
    # Add your cleaning logic here (e.g., lowercasing, removing special characters, etc.)
    return " ".join(api_calls.lower().split())

# Load existing vectorizer and model
tfidf, model = load_artifacts()

# Step 1: Read New Malware Samples from File
def read_malware_file(file_path):
    with open(file_path, "r") as f:
        api_calls = f.read().strip()  # Read the entire file content
    return api_calls

# Path to the file containing the new malware API call sequence
MALWARE_FILE_PATH = "/var/www/PFE_FINAL/report_results/report.txt"  # Replace with the actual file path

# Read the new malware sample
new_malware_sample = read_malware_file(MALWARE_FILE_PATH)

# Print the loaded sample to verify it's loaded correctly
print("Loaded API Call Sequence:")
print(new_malware_sample)

# Clean and transform the new malware sample
X_new = tfidf.transform([clean_api_calls(new_malware_sample)])

# Step 2: Prepare Labels for the New Sample
y_new = [1]  # 1 represents malware

# Step 3: Retrain the Model
# Partially fit the existing MLP model with the new malware sample
model.partial_fit(X_new, y_new, classes=[0, 1])  # Specify all possible classes

# Step 4: Save the Updated Artifacts
joblib.dump(tfidf, TFIDF_VECTORIZER_PATH)  # Save the updated vectorizer (if needed)
joblib.dump(model, MLP_MODEL_PATH)        # Save the retrained model

print("Model retraining complete. Updated artifacts saved.")
