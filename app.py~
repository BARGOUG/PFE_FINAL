from flask import Flask, request, jsonify, render_template
import os
import subprocess
import time
import joblib
import requests

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

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VIRUSTOTAL_REPORT_URL = "https://www.virustotal.com/api/v3/analyses/{analysis_id}"
VIRUSTOTAL_FILE_INFO_URL = "https://www.virustotal.com/api/v3/files/{file_hash}"

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

    # Step 1: Get the uploaded file and analysis type
    file = request.files.get("file")
    analysis_type = request.form.get("analysis_type", "dynamic")  # Default to dynamic analysis
    if not file:
        return jsonify({"error": "No file uploaded."}), 400

    # Save the file to the samples directory
    file_path = os.path.join(SAMPLES_UPLOAD_PATH, file.filename)
    file.save(file_path)
    print(f"File saved to: {file_path}")  # Debug log

    try:
        if analysis_type == "dynamic":
            # Perform Dynamic Analysis
            return perform_dynamic_analysis(file_path)
        elif analysis_type == "static":
            # Perform Static Analysis using VirusTotal
            return perform_static_analysis(file_path)
        else:
            return jsonify({"error": "Invalid analysis type selected."}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {e}"}), 500

def perform_dynamic_analysis(file_path):
    """
    Perform dynamic analysis using CAPE sandbox and MLP model.
    Dynamically wait for the report to be generated instead of waiting 360 seconds.
    """
    try:
        # Submit file to CAPE sandbox
        original_dir = os.getcwd()
        os.chdir("/opt/CAPEv2")
        submit_command = [
            "poetry", "run", "python", "/opt/CAPEv2/utils/submit.py",
            "--timeout", "240", file_path
        ]
        subprocess.run(submit_command, check=True)
        print("CAPE analysis started successfully.")
        os.chdir(original_dir)

        # Get the latest analysis number before starting the scan
        initial_analysis_number = get_latest_analysis_number()
        if not initial_analysis_number:
            return jsonify({"error": "Failed to retrieve the initial analysis number."}), 500

        # Wait for the new analysis report to be generated
        print("Waiting for the new analysis report...")
        max_retries = 60  # Maximum number of retries (e.g., 10 minutes with 10-second intervals)
        retry_interval = 10  # Time to wait between checks (in seconds)

        for _ in range(max_retries):
            current_analysis_number = get_latest_analysis_number()
            if current_analysis_number and current_analysis_number > initial_analysis_number:
                # Verify the new report corresponds to the uploaded file
                report_path = os.path.join(CAPE_ANALYSES_PATH, str(current_analysis_number), "reports", "report.json")
                if os.path.exists(report_path):
                    print(f"New analysis report detected. Analysis number: {current_analysis_number}")
                    break
            print("Analysis report not yet available. Waiting...")
            time.sleep(retry_interval)
        else:
            return jsonify({"error": "Max retries reached. Analysis report not generated."}), 500

        # Extract API calls and run MLP testing
        subprocess.run(["python3", EXTRACTED_API_SCRIPT], check=True)
        subprocess.run(["python3", MLP_TESTING_SCRIPT], check=True)

        # Run MLP prediction logic
        mlp_results = run_mlp_testing()
        if "error" in mlp_results:
            return jsonify(mlp_results), 500

        # Clear samples directory
        for file_name in os.listdir(SAMPLES_UPLOAD_PATH):
            os.remove(os.path.join(SAMPLES_UPLOAD_PATH, file_name))

        # Prepare response
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
    except Exception as e:
        return jsonify({"error": f"Dynamic analysis failed: {e}"}), 500

def perform_static_analysis(file_path):
    """
    Perform static analysis using VirusTotal API and return all available information.
    """
    try:
        # Step 1: Upload the file to VirusTotal
        print(f"Uploading file '{file_path}' to VirusTotal...")
        analysis_id = upload_file_to_virustotal(file_path)
        if not analysis_id:
            return jsonify({"error": "Failed to upload file to VirusTotal."}), 500

        print(f"File uploaded successfully. Analysis ID: {analysis_id}")

        # Step 2: Wait for the analysis to complete
        print("Waiting for analysis to complete...")
        analysis_results = wait_for_analysis_completion(analysis_id)
        if not analysis_results:
            return jsonify({"error": "Failed to retrieve analysis results from VirusTotal."}), 500

        # Step 3: Extract file hash
        file_hash = analysis_results.get("meta", {}).get("file_info", {}).get("sha256", "")
        if not file_hash:
            return jsonify({"error": "Failed to retrieve file hash from VirusTotal."}), 500

        # Step 4: Retrieve detailed file information
        file_details = get_file_details(file_hash)
        if not file_details:
            return jsonify({"error": "Failed to retrieve detailed file information from VirusTotal."}), 500

        # Step 5: Prepare and return the response
        attributes = file_details.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        return jsonify({
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0)
                    },
                    "file_details": attributes,
                    "full_virustotal_report": analysis_results
                }
            }
        }), 200
    except Exception as e:
        return jsonify({"error": f"Static analysis failed: {e}"}), 500

def upload_file_to_virustotal(file_path):
    """
    Uploads a file to VirusTotal for scanning.
    
    Args:
        file_path (str): Path to the file to be uploaded.
    
    Returns:
        str: Analysis ID returned by VirusTotal.
    """
    try:
        with open(file_path, "rb") as file:
            files = {"file": file}
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.post(VIRUSTOTAL_UPLOAD_URL, files=files, headers=headers)
            response.raise_for_status()
            result = response.json()
            analysis_id = result["data"]["id"]
            return analysis_id
    except FileNotFoundError:
        return None
    except requests.exceptions.RequestException:
        return None

def get_virustotal_analysis(analysis_id):
    """
    Retrieves the analysis results from VirusTotal.
    
    Args:
        analysis_id (str): The analysis ID returned after uploading the file.
    
    Returns:
        dict: Analysis results from VirusTotal.
    """
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url = VIRUSTOTAL_REPORT_URL.format(analysis_id=analysis_id)
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()
        return result
    except requests.exceptions.RequestException:
        return None

def get_file_details(file_hash):
    """
    Retrieves detailed file information from VirusTotal.
    
    Args:
        file_hash (str): SHA-256 hash of the file.
    
    Returns:
        dict: Detailed file information.
    """
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url = VIRUSTOTAL_FILE_INFO_URL.format(file_hash=file_hash)
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()
        return result
    except requests.exceptions.RequestException:
        return None

def wait_for_analysis_completion(analysis_id, max_retries=10, retry_interval=30):
    """
    Waits for the analysis to complete and retrieves the final results.
    
    Args:
        analysis_id (str): The analysis ID returned after uploading the file.
        max_retries (int): Maximum number of retries to check analysis status.
        retry_interval (int): Time to wait (in seconds) between retries.
    
    Returns:
        dict: Final analysis results.
    """
    for _ in range(max_retries):
        analysis_results = get_virustotal_analysis(analysis_id)
        if not analysis_results:
            return None
        status = analysis_results.get("data", {}).get("attributes", {}).get("status", "")
        if status == "completed":
            return analysis_results
        elif status == "queued":
            print("Analysis is still queued. Waiting...")
            time.sleep(retry_interval)
        else:
            return None
    print("Max retries reached. Analysis may still be in progress.")
    return None

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)  # Disable debug mode reloading
