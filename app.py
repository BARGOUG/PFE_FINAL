from flask import Flask, request, jsonify, render_template
import os
import subprocess
import time
import joblib

app = Flask(__name__)
app.secret_key = "your_secret_key_here"

# Paths
CAPE_ANALYSES_PATH = "/opt/CAPEv2/storage/analyses"
SAMPLES_UPLOAD_PATH = "/var/www/PFE_FINAL/samples/"
MLP_TESTING_SCRIPT = "/var/www/PFE_FINAL/model_training_testing/MLP_testing.py"
EXTRACTED_API_SCRIPT = "/var/www/PFE_FINAL/extracted_api_from_report.py"
REPORT_RESULTS_PATH = "/var/www/PFE_FINAL/report_results/report.txt"

# Absolute paths for the model and vectorizer
TFIDF_VECTORIZER_PATH = "/var/www/PFE_FINAL/model_training_testing/tfidf_vectorizer.pkl"
MLP_MODEL_PATH = "/var/www/PFE_FINAL/model_training_testing/mlp_neural_network_model.pkl"

# Helper Functions
def get_latest_analysis_number():
    """Extract the latest analysis number from CAPE analyses directory."""
    try:
        directories = [d for d in os.listdir(CAPE_ANALYSES_PATH) if d.isdigit()]
        numeric_dirs = [int(d) for d in directories]
        return max(numeric_dirs) if numeric_dirs else None
    except Exception as e:
        print(f"Error getting latest analysis number: {e}")
        return None

def run_mlp_testing():
    """
    Run the MLP testing script and return the prediction results.
    
    Returns:
        dict: Prediction results from the MLP model.
    """
    # Load the TF-IDF vectorizer
    tfidf = joblib.load(TFIDF_VECTORIZER_PATH)

    # Define the cleaning function
    def clean_api_calls(api_sequence):
        cleaned_sequence = " ".join([call.split('.')[-1] for call in api_sequence.split()])
        return cleaned_sequence

    # Read API calls from the report file
    try:
        with open(REPORT_RESULTS_PATH, "r", encoding="utf-8") as file:
            sample_api_calls = file.read().strip()  # Read and remove leading/trailing whitespace
    except FileNotFoundError:
        return {"error": f"The file '{REPORT_RESULTS_PATH}' was not found."}
    except Exception as e:
        return {"error": f"Error reading the file: {e}"}

    # Clean the input
    cleaned_calls = clean_api_calls(sample_api_calls)

    # Transform the input using the TF-IDF vectorizer
    X_input = tfidf.transform([cleaned_calls])

    # Load the MLP model
    model = joblib.load(MLP_MODEL_PATH)

    # Make predictions
    probability = model.predict_proba(X_input)[0][1]  # Probability of being malware
    prediction = "Malware" if probability >= 0.5 else "Goodware"

    # Return results
    return {
        "predicted_label": prediction,
        "malware_probability": float(probability)
    }

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/scan-file", methods=["POST"])
def scan_file():
    print("Scan request received.")  # Debug log

    # Step 1: Get the uploaded file
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded."}), 400

    # Save the file to the samples directory
    file_path = os.path.join(SAMPLES_UPLOAD_PATH, file.filename)
    file.save(file_path)
    print(f"File saved to: {file_path}")  # Debug log

    # Step 2: Temporarily change to the CAPE directory
    try:
        original_dir = os.getcwd()
        os.chdir("/opt/CAPEv2")
        print("Changed directory to /opt/CAPEv2")  # Debug log

        # Step 3: Start CAPE analysis
        submit_command = [
            "poetry", "run", "python", "/opt/CAPEv2/utils/submit.py",
            "--timeout", "240", file_path
        ]
        subprocess.run(submit_command, check=True)
        print("CAPE analysis started successfully.")  # Debug log

        # Return to the original directory
        os.chdir(original_dir)
        print(f"Returned to original directory: {os.getcwd()}")  # Debug log

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Error submitting file to CAPE: {e}"}), 500
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {e}"}), 500

    # Step 4: Wait for 360 seconds (6 minutes)
    print("Waiting for 360 seconds...")  # Debug log
    time.sleep(360)

    # Step 5: Run the `extracted_api_from_report.py` script
    try:
        subprocess.run(["python3", EXTRACTED_API_SCRIPT], check=True)
        print("Extracted API calls successfully.")  # Debug log
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Error running extracted_api_from_report.py: {e}"}), 500

    # Step 6: Run the MLP testing script
    try:
        subprocess.run(["python3", MLP_TESTING_SCRIPT], check=True)
        print("MLP testing completed successfully.")  # Debug log
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Error running MLP testing script: {e}"}), 500

    # Step 7: Run the MLP prediction logic
    mlp_results = run_mlp_testing()
    if "error" in mlp_results:
        return jsonify(mlp_results), 500

    # Step 8: Clear the samples directory
    try:
        for file_name in os.listdir(SAMPLES_UPLOAD_PATH):
            file_to_remove = os.path.join(SAMPLES_UPLOAD_PATH, file_name)
            os.remove(file_to_remove)
        print("Cleared all files from samples directory.")  # Debug log
    except Exception as e:
        return jsonify({"error": f"Error clearing samples directory: {e}"}), 500

    # Step 9: Prepare the response and send it to the frontend
    return jsonify({
        "data": {
            "attributes": {
                "status": "completed",
                "stats": {
                    "malicious": 1 if mlp_results["predicted_label"] == "Malware" else 0
                },
                "mlp_prediction": mlp_results
            }
        }
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)  # Disable debug mode reloading
