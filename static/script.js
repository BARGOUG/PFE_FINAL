document.addEventListener('DOMContentLoaded', () => {
  const fileInput = document.getElementById('fileInput');
  const uploadLabel = document.getElementById('uploadLabel');
  const scanButton = document.getElementById('scanButton');
  const progressSection = document.getElementById('progressSection');
  const progress = document.getElementById('progress');
  const progressText = document.getElementById('progressText');
  const resultsSection = document.getElementById('resultsSection');
  const fileNameDisplay = document.getElementById('fileName');
  const fileSizeDisplay = document.getElementById('fileSize');
  const scanStatusDisplay = document.getElementById('scanStatus');
  const threatDetectedDisplay = document.getElementById('threatDetected');
  const malwareProbabilityDisplay = document.getElementById('malwareProbability');
  const probabilityValueDisplay = document.getElementById('probabilityValue');
  const antivirusResultsDisplay = document.getElementById('antivirusResults');

  let selectedFile = null;
  let isScanning = false;

  // Enable scan button when a file is selected
  fileInput.addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (!file) {
      console.error('No file selected.');
      return;
    }

    // Validate file size (optional)
    const maxSize = 650 * 1024 * 1024; // 650 MB
    if (file.size > maxSize) {
      alert('File size exceeds the limit of 650 MB.');
      return;
    }

    console.log('Selected file:', file);
    selectedFile = file;

    // Update the label text to show the selected file name
    uploadLabel.querySelector('span').textContent = `Selected: ${file.name}`;
    scanButton.disabled = false;
  });

  // Handle click on the label to trigger file input
  uploadLabel.addEventListener('click', () => {
    fileInput.click();
  });

  // Handle scan button click
  scanButton.addEventListener('click', async () => {
    if (!selectedFile || isScanning) {
      alert('Please select a file before scanning or wait for the current scan to finish.');
      return;
    }

    // Prevent multiple scans
    isScanning = true;

    // Display progress section
    progressSection.style.display = 'block';
    resultsSection.style.display = 'none';

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      // Add analysis type
      const analysisType = document.getElementById('analysisType').value;
      formData.append('analysis_type', analysisType);

      let progressValue = 0;
      const interval = setInterval(() => {
        progressValue += 10;
        if (progressValue > 100) {
          clearInterval(interval);
          progressText.textContent = 'Scanning in progress...';
        } else {
          progress.style.width = `${progressValue}%`;
          progressText.textContent = `Uploading... ${progressValue}%`;
        }
      }, 500);

      const response = await fetch('http://localhost:5000/scan-file', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Failed to scan file.');
      }

      const result = await response.json();

      setTimeout(() => {
        // Display basic results
        fileNameDisplay.textContent = selectedFile.name;
        fileSizeDisplay.textContent = `${(selectedFile.size / 1024).toFixed(2)} KB`;
        scanStatusDisplay.textContent = result.data.attributes.status;

        // Handle stats
        const stats = result.data.attributes.stats;
        threatDetectedDisplay.textContent =
          stats.malicious > 0
            ? 'Threat detected'
            : 'No threats detected';

        // Check if analysis type is dynamic
        if (result.data.attributes.mlp_prediction) {
          const mlpPrediction = result.data.attributes.mlp_prediction;
          const probability = mlpPrediction.malware_probability;

          // Show malware probability
          malwareProbabilityDisplay.style.display = 'block';
          probabilityValueDisplay.textContent = `${(probability * 100).toFixed(2)}%`;
        } else {
          malwareProbabilityDisplay.style.display = 'none';
        }

        // Check if analysis type is static
        if (result.data.attributes.file_details) {
          const antivirusResults = result.data.attributes.file_details.last_analysis_results;
          let antivirusDetailsHTML = "<h3>Antivirus Results:</h3>";
          for (const [engine, result] of Object.entries(antivirusResults)) {
            antivirusDetailsHTML += `
              <div>
                <strong>${engine}:</strong>
                <span>Category: ${result.category || 'N/A'}</span>,
                <span>Result: ${result.result || 'N/A'}</span>
              </div>
            `;
          }
          antivirusResultsDisplay.innerHTML = antivirusDetailsHTML;
        } else {
          antivirusResultsDisplay.innerHTML = '';
        }

        resultsSection.style.display = 'block';
      }, 500);
    } catch (error) {
      console.error('Error scanning file:', error);
      progressText.textContent = 'An error occurred during scanning.';
    } finally {
      isScanning = false;
      scanButton.disabled = false;
    }
  });
});
