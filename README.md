QR Code Security Scanner

This application scans QR codes, analyzes URLs for potential threats, and performs security checks to detect phishing attempts, blacklisted domains, malicious file types, and payment-related URLs. It is designed to be user-friendly and efficient, providing real-time security checks for QR codes.

Features:

Scans QR codes from images or camera input.
Detects phishing attempts and compares URLs against a list of legitimate sites.
Blocks malicious downloads (e.g., executable files).
Checks for blacklisted domains and redirects.
Logs scans and provides statistics and scan history.
Provides alerts for payment-related URLs.
Requirements:

To run this application, you will need the following:

Python 3.x installed on your system.
Required Python packages:
opencv-python
pyzbar
requests
tkinter (should be pre-installed with Python)
fuzzywuzzy
whois
Pillow
matplotlib
You can install the required packages using the following pip commands:

nginx
Copy
Edit
pip install opencv-python pyzbar requests fuzzywuzzy whois Pillow matplotlib
Note: tkinter is usually pre-installed with Python, but if you don’t have it, you can install it via your package manager (e.g., sudo apt-get install python3-tk for Linux).

How to Run:

after extraction and package installation, run the programme by editing it on your IDE of choice e.g PyCharm or pythons default IDE 
Using the Application:

Enter URL Manually: Type a URL into the input field and press the "Scan URL" button to analyze it.
Scan QR Code from File: Click "Scan QR from File" to open a file dialog, select an image containing a QR code, and the URL will be extracted and analyzed.
Scan QR Code from Camera: Click "Scan QR from Camera" to activate your webcam and scan QR codes in real time. Press the 'q' key to exit the camera feed.
Show Scan Statistics: Click "Show Statistics" to view a bar chart with scan statistics (e.g., threat detections).
View Scan History: Click "Show Scan History" to view the log of all previously scanned URLs along with their results.
Logs and History:

Scan Logs: The scan results are saved in a text file called scan_logs.txt. Each scan entry includes the timestamp, scanned URL, and results of the security checks.
Scan History: The application keeps a history of all scans, which can be accessed by clicking the "Show Scan History" button.
Troubleshooting:

No QR Code Detected: If no QR code is detected from the image or camera feed, ensure that the image has a valid QR code and that the camera is working properly.
No Internet Connection: Ensure you are connected to the internet to allow the application to check URLs and perform whois lookups, redirects, and domain validation.
Module Not Found: If you get a ModuleNotFoundError, ensure that all required libraries are installed. Run pip install -r requirements.txt to install them.
Contributions:

If you would like to contribute to this project, feel free to fork the repository and submit a pull request with your changes. Any improvements, bug fixes, or feature requests are welcome.
