#Ashley Stainsby
#b1077548
#final project 2025
import os
import cv2
import requests
import tkinter as tk
from tkinter import filedialog, messagebox
from pyzbar.pyzbar import decode
from fuzzywuzzy import fuzz
import whois
from urllib.parse import urlparse
from PIL import Image, ImageTk
from datetime import datetime
import matplotlib.pyplot as plt
from collections import defaultdict

# Define blocked file types
BLOCKED_EXTENSIONS = {".exe", ".bat", ".sh", ".msi", ".cmd", ".vbs"}

# List of known legitimate domains
LEGITIMATE_SITES = ["paypal.com", "amazon.com", "bankofamerica.com", "google.com", "microsoft.com", "apple.com"]

# Payment-related keywords
PAYMENT_KEYWORDS = ["checkout", "payment", "securepay", "pay", "transaction", "billing"]

# Blacklisted malicious domains
BLACKLISTED_DOMAINS = ["malicious-site.com", "fraudpay.com", "hackerzone.net", "fakebanking.com", "phishingsite.org"]

LOG_FILE = "scan_logs.txt"
threat_counts = defaultdict(int)
scan_history = []

def log_scan(url, results):
    """Save scan results to a log file and update history."""
    scan_entry = f"Scanned URL: {url}\n" + "\n".join(results)
    scan_history.append(scan_entry)
    with open(LOG_FILE, "a") as log:
        log.write(f"\n=== Scan Timestamp: {datetime.now()} ===\n")
        log.write(scan_entry + "\n" + "=" * 40 + "\n")

def is_executable_file(url):
    return os.path.splitext(url)[-1].lower() in BLOCKED_EXTENSIONS

def is_payment_url(url):
    return any(keyword in url.lower() for keyword in PAYMENT_KEYWORDS)

def check_phishing_url(scanned_url):
    try:
        domain = urlparse(scanned_url).netloc
        for legit_domain in LEGITIMATE_SITES:
            if fuzz.ratio(domain, legit_domain) > 80:
                return f"[WARNING] Possible phishing attempt! {domain} looks like {legit_domain}."
        return "[SAFE] No phishing detected."
    except:
        return "[ERROR] Invalid URL format."

def check_blacklist(url):
    return f"[BLOCKED] This site is blacklisted: {urlparse(url).netloc}" if urlparse(url).netloc in BLACKLISTED_DOMAINS else "[SAFE] Domain not blacklisted."

def check_redirects(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        return f"[WARNING] Redirect detected! Final destination: {response.url}" if response.url != url else "[SAFE] No redirects detected."
    except requests.exceptions.RequestException:
        return "[ERROR] Unable to fetch the URL."

def check_url_security(url):
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL or scan a QR code.")
        return

    results = []
    if is_executable_file(url):
        results.append("[BLOCKED] Executable file detected. Download prevented.")
    if is_payment_url(url):
        results.append("[ALERT] Payment system detected. Be cautious!")
    results.append(check_phishing_url(url))
    results.append(check_blacklist(url))
    results.append(check_redirects(url))

    try:
        domain_info = whois.whois(urlparse(url).netloc)
        if domain_info.get("creation_date"):
            results.append(f"[INFO] Domain found. Created on {domain_info['creation_date'][0]}")
        else:
            results.append("[WARNING] No domain registration date found. Possible suspicious site.")
    except:
        results.append("[ERROR] WHOIS lookup failed.")

    log_scan(url, results)
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Scanned URL: {url}\n" + "\n".join(results))
    result_text.config(state=tk.DISABLED)

def scan_qr_from_file():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
    if not file_path:
        return
    img = cv2.imread(file_path)
    qr_codes = decode(img)
    if qr_codes:
        qr_data = qr_codes[0].data.decode("utf-8")
        entry_url.delete(0, tk.END)
        entry_url.insert(0, qr_data)
        check_url_security(qr_data)
    else:
        messagebox.showerror("QR Code Error", "No QR Code detected in the image.")

def scan_qr_from_camera():
    cap = cv2.VideoCapture(0)
    while True:
        ret, frame = cap.read()
        qr_codes = decode(frame)
        for qr in qr_codes:
            qr_data = qr.data.decode("utf-8")
            cap.release()
            cv2.destroyAllWindows()
            entry_url.delete(0, tk.END)
            entry_url.insert(0, qr_data)
            check_url_security(qr_data)
            return
        cv2.imshow("QR Code Scanner - Press 'q' to Exit", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break
    cap.release()
    cv2.destroyAllWindows()

def show_scan_statistics():
    total_scans = len(scan_history)  # Count total scans performed
    total_threats = sum(threat_counts.values())  # Count total detected threats
    
    if total_scans == 0:
        messagebox.showinfo("Statistics", "No scan data available.")
        return
    
    if not threat_counts:  # No threats detected
        messagebox.showinfo("Statistics", f"Total Scans: {total_scans}\nNo threats detected.")
        return
    
    labels, values = zip(*threat_counts.items())

    plt.figure(figsize=(9, 5))
    plt.barh(labels, values, color="red")
    plt.xlabel("Number of Detections")
    plt.ylabel("Threat Type")
    plt.title("Scan Threat Statistics")
    plt.show()
    
    # Display scan summary in a message box
    messagebox.showinfo("Scan Summary", f"Total Scans: {total_scans}\nPotential Threats Blocked: {total_threats}")



def show_scan_history():
    history_window = tk.Toplevel(root)
    history_window.title("Scan History")
    history_window.geometry("600x400")
    text_widget = tk.Text(history_window, wrap=tk.WORD)
    text_widget.pack(expand=True, fill=tk.BOTH)
    text_widget.insert(tk.END, "\n\n".join(scan_history))
    text_widget.config(state=tk.DISABLED)

root = tk.Tk()
root.title("QR Code Security Scanner")
root.geometry("600x600")

tk.Label(root, text="Enter QR Code URL:", font=("Arial", 12)).pack(pady=5)
entry_url = tk.Entry(root, width=50)
entry_url.pack(pady=5)

tk.Button(root, text="Scan URL", command=lambda: check_url_security(entry_url.get())).pack(pady=5)
tk.Button(root, text="Scan QR from File", command=scan_qr_from_file).pack(pady=5)
tk.Button(root, text="Scan QR from Camera", command=scan_qr_from_camera).pack(pady=5)
tk.Button(root, text="Show Statistics", command=show_scan_statistics).pack(pady=5)
tk.Button(root, text="Show Scan History", command=show_scan_history).pack(pady=5)

result_text = tk.Text(root, height=12, width=75, state=tk.DISABLED)
result_text.pack(pady=5)

root.mainloop()
import os
import cv2
import requests
import tkinter as tk
from tkinter import filedialog, messagebox
from pyzbar.pyzbar import decode
from fuzzywuzzy import fuzz
from urllib.parse import urlparse, urlunparse
from datetime import datetime
import matplotlib.pyplot as plt
from collections import defaultdict

# Define blocked file types
BLOCKED_EXTENSIONS = {".exe", ".bat", ".sh", ".msi", ".cmd", ".vbs", ".zip"}

# List of known legitimate domains for phishing comparison
LEGITIMATE_SITES = [
    "paypal.com", "amazon.com", "bankofamerica.com", "google.com",
    "microsoft.com", "apple.com", "facebook.com", "instagram.com", "twitter.com",
    "netflix.com", "ebay.com", "linkedin.com", "wikipedia.org"
]

# Payment-related keywords
PAYMENT_KEYWORDS = ["checkout", "payment", "securepay", "pay", "transaction", "billing", "invoice"]

# Blacklisted phishing/malicious domains
BLACKLISTED_DOMAINS = ["malicious-site.com", "fraudpay.com", "hackerzone.net", "fakebanking.com", "phishingsite.org", "scam-login.com"]

LOG_FILE = "scan_logs.txt"
threat_counts = defaultdict(int)
scan_history = []

def log_scan(url, results):
    """Save scan results to a log file and update statistics"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_history.append((timestamp, url, results))
    
    with open(LOG_FILE, "a") as log:
        log.write(f"\n=== Scan Timestamp: {timestamp} ===\n")
        log.write(f"Scanned URL: {url}\n")
        for result in results:
            log.write(f"{result}\n")
            if any(tag in result for tag in ["[BLOCKED]", "[ALERT]", "[WARNING]"]):
                threat_counts[result.split("]")[0] + "]"] += 1
        log.write("=" * 40 + "\n")

def is_executable_file(url):
    """Check if the file has a blocked extension"""
    file_extension = os.path.splitext(url)[-1].lower()
    return file_extension in BLOCKED_EXTENSIONS

def is_payment_url(url):
    """Check if the URL contains payment-related terms"""
    return any(keyword in url.lower() for keyword in PAYMENT_KEYWORDS)

def check_phishing_url(scanned_url):
    """Compare scanned URL against known legitimate websites"""
    try:
        parsed_url = urlparse(scanned_url)
        domain = parsed_url.netloc.lower()
        
        for legit_domain in LEGITIMATE_SITES:
            similarity = fuzz.ratio(domain, legit_domain)
            if similarity > 70:  # 70% similarity threshold
                return f"[WARNING] Possible phishing attempt! {domain} looks like {legit_domain}."
        return "[SAFE] No phishing detected."
    except:
        return "[ERROR] Invalid URL format."

def check_blacklist(url):
    """Check if the domain is blacklisted"""
    domain = urlparse(url).netloc.lower()
    if domain in BLACKLISTED_DOMAINS:
        return f"[BLOCKED] This site is blacklisted: {domain}"
    return "[SAFE] Domain not blacklisted."

def check_redirects(url):
    """Check if the URL redirects to another page"""
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        final_url = response.url
        if final_url != url:
            return f"[WARNING] Redirect detected! Final destination: {final_url}"
        return "[SAFE] No redirects detected."
    except requests.exceptions.RequestException:
        return "[ERROR] Unable to fetch the URL."

def check_url_security(url):
    """Runs multiple security checks and updates the GUI"""
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL or scan a QR code.")
        return

    results = []

    # Check for executable files
    if is_executable_file(url):
        results.append("[BLOCKED] Executable file detected. Download prevented.")

    # Check for payment systems
    if is_payment_url(url):
        results.append("[ALERT] Payment system detected. Be cautious!")

    # Check for phishing attempts
    phishing_result = check_phishing_url(url)
    results.append(phishing_result)

    # Check if URL is in blacklist
    blacklist_result = check_blacklist(url)
    results.append(blacklist_result)

    # Check for hidden redirects
    redirect_result = check_redirects(url)
    results.append(redirect_result)

    # Log the results
    log_scan(url, results)

    # Display results in GUI
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Scanned URL: {url}\n" + "\n".join(results))
    result_text.config(state=tk.DISABLED)

def scan_qr_from_file():
    """Opens a file dialog to select an image and extracts QR code URL"""
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
    if not file_path:
        return
    img = cv2.imread(file_path)
    qr_codes = decode(img)
    if qr_codes:
        qr_data = qr_codes[0].data.decode("utf-8")
        entry_url.delete(0, tk.END)
        entry_url.insert(0, qr_data)
        check_url_security(qr_data)
    else:
        messagebox.showerror("QR Code Error", "No QR Code detected in the image.")

def show_scan_history():
    """Show a history of all scans with timestamps."""
    history_window = tk.Toplevel(root)
    history_window.title("Scan History")
    history_text = tk.Text(history_window, width=80, height=20)
    history_text.pack()
    for timestamp, url, results in scan_history:
        history_text.insert(tk.END, f"[{timestamp}] {url}\n" + "\n".join(results) + "\n\n")

def show_scan_statistics():
    """Display a bar chart of scan statistics"""
    if not threat_counts:
        messagebox.showinfo("Statistics", "No scan data available.")
        return
    labels, values = zip(*threat_counts.items())
    plt.figure(figsize=(10, 6))
    plt.bar(labels, values, color="red")
    plt.xlabel("Threat Type")
    plt.ylabel("Number of Detections")
    plt.title("Scan Threat Statistics")
    plt.xticks(rotation=30, ha="right")
    plt.show()

root.mainloop()
