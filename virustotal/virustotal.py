import os
import requests
import argparse
import time
from pprint import pprint

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VIRUSTOTAL_REPORT_URL = "https://www.virustotal.com/api/v3/analyses/{analysis_id}"
VIRUSTOTAL_FILE_INFO_URL = "https://www.virustotal.com/api/v3/files/{file_hash}"

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
        print(f"Error: File '{file_path}' not found.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error uploading file to VirusTotal: {e}")
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
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving analysis from VirusTotal: {e}")
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
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving file details from VirusTotal: {e}")
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
            print(f"Unexpected status: {status}")
            return None

    print("Max retries reached. Analysis may still be in progress.")
    return None

def display_detailed_results(file_hash, analysis_results):
    """
    Displays detailed analysis results.
    
    Args:
        file_hash (str): SHA-256 hash of the file.
        analysis_results (dict): Full analysis results from VirusTotal.
    """
    # Retrieve detailed file information
    file_details = get_file_details(file_hash)
    if not file_details:
        print("Failed to retrieve detailed file information.")
        return

    attributes = file_details.get("data", {}).get("attributes", {})
    print("\nDetailed Analysis Results:")
    print(f"File Name: {attributes.get('meaningful_name', 'N/A')}")
    print(f"SHA-256 Hash: {file_hash}")
    print(f"File Size: {attributes.get('size', 'N/A')} bytes")
    print(f"File Type: {attributes.get('type_description', 'N/A')}")
    print(f"Upload Date: {attributes.get('first_submission_date', 'N/A')}")
    print(f"Last Analysis Date: {attributes.get('last_analysis_date', 'N/A')}")

    # Display antivirus engine results
    print("\nAntivirus Engine Results:")
    last_analysis_results = attributes.get("last_analysis_results", {})
    for engine, result in last_analysis_results.items():
        print(f"\nEngine: {engine}")
        print(f"  Category: {result.get('category', 'N/A')}")
        print(f"  Result: {result.get('result', 'N/A')}")
        print(f"  Method: {result.get('method', 'N/A')}")
        print(f"  Update: {result.get('engine_update', 'N/A')}")

    # Display overall statistics
    stats = attributes.get("last_analysis_stats", {})
    print("\nOverall Statistics:")
    print(f"Malicious: {stats.get('malicious', 0)}")
    print(f"Suspicious: {stats.get('suspicious', 0)}")
    print(f"Harmless: {stats.get('harmless', 0)}")
    print(f"Undetected: {stats.get('undetected', 0)}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Scan a file using VirusTotal API.")
    parser.add_argument("file_path", type=str, help="Path to the file to scan.")
    args = parser.parse_args()

    # Step 1: Upload the file to VirusTotal
    print(f"Uploading file '{args.file_path}' to VirusTotal...")
    analysis_id = upload_file_to_virustotal(args.file_path)
    if not analysis_id:
        print("Failed to upload file.")
        return

    print(f"File uploaded successfully. Analysis ID: {analysis_id}")

    # Step 2: Wait for the analysis to complete
    print("Waiting for analysis to complete...")
    analysis_results = wait_for_analysis_completion(analysis_id)
    if not analysis_results:
        print("Failed to retrieve analysis results.")
        return

    # Extract file hash
    file_hash = analysis_results.get("meta", {}).get("file_info", {}).get("sha256", "")
    if not file_hash:
        print("Failed to retrieve file hash.")
        return

    # Step 3: Display detailed analysis results
    display_detailed_results(file_hash, analysis_results)

if __name__ == "__main__":
    main()
