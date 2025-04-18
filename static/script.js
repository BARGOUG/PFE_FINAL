document.addEventListener("DOMContentLoaded", () => {
  const fileInput = document.getElementById("fileInput");
  const uploadLabel = document.getElementById("uploadLabel");
  const scanButton = document.getElementById("scanButton");
  const progressSection = document.getElementById("progressSection");
  const progress = document.getElementById("progress");
  const progressText = document.getElementById("progressText");
  const resultsSection = document.getElementById("resultsSection");
  const fileNameElement = document.getElementById("fileName");
  const fileSizeElement = document.getElementById("fileSize");
  const scanStatusElement = document.getElementById("scanStatus");
  const threatDetectedElement = document.getElementById("threatDetected");
  const malwareProbabilityElement = document.getElementById("malwareProbability");
  const probabilityValueElement = document.getElementById("probabilityValue");
  const antivirusResultsContainer = document.getElementById("antivirusResults");

  // Enable the Scan Button when a file is selected
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      scanButton.disabled = false;
      const file = fileInput.files[0];
      fileNameElement.textContent = file.name;
      fileSizeElement.textContent = `${(file.size / 1024).toFixed(2)} KB`;
      uploadLabel.innerHTML = `
        <i class="fas fa-check-circle"></i>
        <span>File Selected: ${file.name}</span>
      `;
    } else {
      scanButton.disabled = true;
      uploadLabel.innerHTML = `
        <i class="fas fa-cloud-upload-alt"></i>
        <span>Choose a file or drag it here</span>
        <small>Supported formats: Any</small>
      `;
    }
  });

  // Handle File Upload and Analysis
  scanButton.addEventListener("click", async () => {
    const file = fileInput.files[0];
    const analysisType = document.getElementById("analysisType").value;

    if (!file) {
      alert("Please select a file to scan.");
      return;
    }

    // Show progress section
    progressSection.style.display = "block";
    resultsSection.style.display = "none";
    progress.style.width = "0%";
    progressText.textContent = "Initializing scan...";

    try {
      // Simulate progress bar animation
      let progressValue = 0;
      const interval = setInterval(() => {
        if (progressValue >= 90) {
          clearInterval(interval);
        }
        progressValue += 10;
        progress.style.width = `${progressValue}%`;
        progressText.textContent = `Scanning in progress... ${progressValue}%`;
      }, 300);

      // Send file to Flask backend for analysis
      const formData = new FormData();
      formData.append("file", file);
      formData.append("analysis_type", analysisType);

      const response = await fetch("/scan-file", {
        method: "POST",
        body: formData,
      });

      clearInterval(interval); // Stop progress bar animation
      progress.style.width = "100%";
      progressText.textContent = "Finalizing results...";

      const result = await response.json();

      if (response.ok) {
        // Display results
        displayResults(result.data.attributes, analysisType);
      } else {
        throw new Error(result.error || "An error occurred during the scan.");
      }
    } catch (error) {
      alert(`Error: ${error.message}`);
    } finally {
      progressText.textContent = "Scan completed.";
    }
  });

  /**
   * Display scan results based on the analysis type.
   * @param {Object} attributes - The scan results from the backend.
   * @param {string} analysisType - The type of analysis performed ("dynamic" or "static").
   */
  function displayResults(attributes, analysisType) {
    resultsSection.style.display = "block";
    scanStatusElement.textContent = attributes.status;

    if (analysisType === "dynamic") {
      // Dynamic Analysis Results
      const mlpPrediction = attributes.mlp_prediction;
      threatDetectedElement.textContent =
        mlpPrediction.predicted_label === "Malware" ? "Yes" : "No";

      malwareProbabilityElement.style.display = "flex";
      probabilityValueElement.textContent = `${(mlpPrediction.malware_probability * 100).toFixed(
        2
      )}%`;

      // Clear antivirus results container
      antivirusResultsContainer.innerHTML = "";
    } else if (analysisType === "static") {
      // Static Analysis Results
      const stats = attributes.stats;
      threatDetectedElement.textContent = stats.malicious > 0 ? "Yes" : "No";

      // Clear malware probability section
      malwareProbabilityElement.style.display = "none";

      // Extract and display antivirus results
      const antivirusResults = attributes.file_details?.last_analysis_results || {};
      displayAntivirusResults(antivirusResults);
    }
  }

  /**
   * Dynamically populate antivirus results into the UI.
   * @param {Object} antivirusResults - The antivirus results from the VirusTotal report.
   */
  function displayAntivirusResults(antivirusResults) {
    antivirusResultsContainer.innerHTML = ""; // Clear previous results

    // Add heading
    const heading = document.createElement("h3");
    heading.innerHTML = '<i class="fas fa-shield-alt"></i> Antivirus Results:';
    antivirusResultsContainer.appendChild(heading);

    // Check if antivirusResults is empty
    if (!antivirusResults || Object.keys(antivirusResults).length === 0) {
      const noResults = document.createElement("div");
      noResults.classList.add("result-item");
      noResults.textContent = "No antivirus results available.";
      antivirusResultsContainer.appendChild(noResults);
      return;
    }

    // Loop through antivirus results and create result items
    for (const [engine, result] of Object.entries(antivirusResults)) {
      const resultItem = document.createElement("div");
      resultItem.classList.add("result-item");

      // Engine Name
      const engineName = document.createElement("span");
      engineName.classList.add("engine-name");
      engineName.textContent = engine;

      // Category
      const category = document.createElement("span");
      category.classList.add("category");
      category.textContent = `Category: ${result.category || "N/A"}`;

      // Result
      const resultText = document.createElement("span");
      resultText.classList.add("result");
      resultText.textContent = `Result: ${result.result || "N/A"}`;

      // Apply color coding based on category
      if (result.category === "undetected") {
        resultText.classList.add("undetected");
      } else if (result.category === "malicious") {
        resultText.classList.add("malicious");
      } else if (result.category === "failure") {
        resultText.classList.add("failure");
      }

      // Append elements to the result item
      resultItem.appendChild(engineName);
      resultItem.appendChild(category);
      resultItem.appendChild(resultText);

      // Append result item to the container
      antivirusResultsContainer.appendChild(resultItem);
    }
  }
});
