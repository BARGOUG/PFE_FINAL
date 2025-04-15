import joblib

# Load the TF-IDF vectorizer
tfidf = joblib.load("tfidf_vectorizer.pkl")

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
    
    # Load all models and make predictions
    model_names = [
        "mlp_neural_network_best"
    ]
    
    results = {}
    for model_name in model_names:
        # Load the model
        model_path = f"{model_name}_model.pkl"
        model = joblib.load(model_path)
        
        # Make predictions
        probability = model.predict_proba(X_input)[0][1]  # Probability of being malware
        prediction = "Malware" if probability >= threshold else "Goodware"
        
        # Store results
        results[model_name] = {
            "predicted_label": prediction,
            "malware_probability": float(probability)
        }
    
    return results

# Example usage
if __name__ == "__main__":
    # Test with a sample API call sequence
    sample_api_calls = """
CoCreateInstance CreateProcessInternalW CreateRemoteThreadEx DeviceIoControl DllLoadNotification GetCommandLineW GetKeyboardLayout GetSystemInfo GetSystemTimeAsFileTime IsDebuggerPresent LdrGetDllHandle LdrGetProcedureAddressForCaller LdrLoadDll LdrpCallInitRoutine LoadLibraryExW LookupPrivilegeValueW MsiInstallProductW NtAddAtomEx NtAllocateVirtualMemory NtClose NtCreateFile NtCreateMutant NtCreateSection NtCreateThreadEx NtCreateUserProcess NtDelayExecution NtDuplicateObject NtFreeVirtualMemory NtMapViewOfSection NtOpenDirectoryObject NtOpenEvent NtOpenFile NtOpenKey NtOpenKeyEx NtOpenProcessToken NtOpenSection NtProtectVirtualMemory NtQueryAttributesFile NtQueryInformationFile NtQueryInformationThread NtQueryInformationToken NtQueryKey NtQueryLicenseValue NtQuerySystemInformation NtQuerySystemTime NtQueryValueKey NtReadFile NtReleaseMutant NtSetInformationFile NtSetInformationProcess NtSetTimerEx NtTerminateProcess NtTerminateThread NtTestAlert NtUnmapViewOfSection NtUnmapViewOfSectionEx NtWaitForSingleObject NtWriteFile PostMessageW PostThreadMessageW RegCloseKey RegNotifyChangeKeyValue RegOpenKeyExW RegQueryValueExW RtlDosPathNameToNtPathName_U RtlSetCurrentTransaction SetUnhandledExceptionFilter StartServiceW    """
    
    # Remove newlines and extra spaces
    sample_api_calls = " ".join(sample_api_calls.split())
    
    # Predict with a custom threshold (e.g., 0.5)
    results = predict_malware(sample_api_calls, threshold=0.5)
    
    # Print results
    print("\nPredictions Across All Models:")
    for model_name, result in results.items():
        print(f"\nModel: {model_name.replace('_', ' ').title()}")
        print(f"Prediction: {result['predicted_label']}")
        print(f"Malware Probability: {result['malware_probability']:.4f}")
