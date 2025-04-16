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

  let selectedFile = null;
  let isScanning = false; // Add a flag to prevent duplicate scans

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
    fileInput.click(); // Programmatically trigger the file input dialog
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
        fileNameDisplay.textContent = selectedFile.name;
        fileSizeDisplay.textContent = `${(selectedFile.size / 1024).toFixed(2)} KB`;
        scanStatusDisplay.textContent = result.data.attributes.status;
        threatDetectedDisplay.textContent =
          result.data.attributes.stats.malicious > 0
            ? 'Threat detected'
            : 'No threats detected';

        // Display MLP prediction details
        const mlpPrediction = result.data.attributes.mlp_prediction;
        threatDetectedDisplay.textContent += ` (${mlpPrediction.predicted_label})`;
        threatDetectedDisplay.textContent += ` (Probability: ${mlpPrediction.malware_probability.toFixed(4)})`;

        resultsSection.style.display = 'block';
      }, 500);
    } catch (error) {
      console.error('Error scanning file:', error);
      progressText.textContent = 'An error occurred during scanning.';
    } finally {
      isScanning = false; // Reset the scanning flag
      scanButton.disabled = false; // Re-enable the scan button
    }
  });
});
