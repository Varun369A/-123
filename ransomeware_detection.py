import os
import hashlib
import tkinter as tk
from tkinter import messagebox, filedialog
from datetime import datetime
import threading
from queue import Queue

# Ransomware Signatures
SIGNATURES = {
    "extensions": [
        ".encrypted", ".locked", ".ransom", ".cry", ".crypto", ".enc", ".locky",
        ".wannacry", ".tesla", ".crypt", ".btc", ".pay", ".paycrypt"
    ],
    "hashes": [
        "275a021bbfb648aa0e5a142d180b71bf",  # Locky ransomware hash
        "ae0d8c2e6c733e0526e3c6d29b151508",  # WannaCry ransomware hash
        "db349b97c37d22f5ea1d1841e3c89eb4",  # NotPetya ransomware hash
        "5d41402abc4b2a76b9719d911017c592",  # Example hash 1
        "6dcd4ce23d88e2ee9568ba546c007c63"   # Example hash 2
    ]
}

class RansomwareAnalysisTool:
    def __init__(self, log_callback):
        self.log_callback = log_callback
        self.suspicious_files = []
        self.detected_signatures = []
        self.queue = Queue()

    def analyze_directory(self, directory):
        """
        Analyze a directory for suspicious file patterns and ransomware signatures using multithreading.
        """
        self.log_callback(f"Starting analysis on: {directory}")
        self.suspicious_files.clear()
        self.detected_signatures.clear()

        # Collect all file paths
        file_paths = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_paths.append(os.path.join(root, file))

        # Determine number of threads
        num_threads = min(50, len(file_paths))  # Max 50 threads or less if fewer files
        self.log_callback(f"Using {num_threads} threads for analysis.")

        # Start threads
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=self.worker)
            threads.append(thread)
            thread.start()

        # Add files to the queue
        for file_path in file_paths:
            self.queue.put(file_path)

        # Wait for all files to be processed
        self.queue.join()

        # Stop threads
        for _ in range(num_threads):
            self.queue.put(None)
        for thread in threads:
            thread.join()

        self.log_callback("Analysis complete.")
        self.log_callback(f"Total suspicious files detected: {len(self.suspicious_files)}")
        self.log_callback(f"Total signature matches: {len(self.detected_signatures)}")

    def worker(self):
        """
        Worker thread to process files from the queue.
        """
        while True:
            file_path = self.queue.get()
            if file_path is None:  # Stop signal
                break
            self.process_file(file_path)
            self.queue.task_done()

    def process_file(self, file_path):
        """
        Process a single file to check for suspicious patterns and signatures.
        """
        # Log processing progress
        self.log_callback(f"Analyzing file: {file_path}")

        # Check for suspicious patterns
        for pattern in SIGNATURES["extensions"]:
            if file_path.endswith(pattern):
                self.suspicious_files.append(file_path)
                self.log_callback(f"[ALERT] Suspicious file detected: {file_path}")

        # Check for known ransomware signatures (hashes)
        file_hash = self.compute_file_hash(file_path)
        if file_hash in SIGNATURES["hashes"]:
            self.detected_signatures.append(file_path)
            self.log_callback(f"[ALERT] Signature match detected: {file_path}")

    @staticmethod
    def compute_file_hash(file_path):
        """
        Compute the MD5 hash of a file.
        """
        try:
            hasher = hashlib.md5()
            with open(file_path, "rb") as file:
                while chunk := file.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            return None

    def generate_report(self, report_path):
        """
        Generate a report summarizing the analysis.
        """
        with open(report_path, "w") as report_file:
            report_file.write("Ransomware Analysis Report\n")
            report_file.write("=" * 40 + "\n")
            report_file.write(f"Analysis Date: {datetime.now()}\n\n")
            report_file.write(f"Total Suspicious Files Detected: {len(self.suspicious_files)}\n")
            report_file.write(f"Total Signature Matches: {len(self.detected_signatures)}\n\n")
            
            if self.suspicious_files:
                report_file.write("Suspicious Files:\n")
                for file in self.suspicious_files:
                    report_file.write(f" - {file}\n")
            
            if self.detected_signatures:
                report_file.write("\nSignature Matches:\n")
                for file in self.detected_signatures:
                    report_file.write(f" - {file}\n")
        return report_path

# GUI Functions
def select_directory():
    path = filedialog.askdirectory()
    if path:
        path_entry.delete(0, tk.END)
        path_entry.insert(0, path)

def log_message(message):
    log_textbox.insert(tk.END, message + "\n")
    log_textbox.see(tk.END)

def start_analysis():
    path = path_entry.get()
    if not os.path.isdir(path):
        messagebox.showerror("Error", "Invalid directory path.")
    else:
        start_button.config(state=tk.DISABLED)
        log_message("Analysis started...")
        analysis_thread = threading.Thread(target=tool.analyze_directory, args=(path,))
        analysis_thread.start()

def save_report():
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt")],
        title="Save Report As"
    )
    if file_path:
        tool.generate_report(file_path)
        messagebox.showinfo("Success", f"Report saved at: {file_path}")

# GUI Setup
root = tk.Tk()
root.title("Ransomware Analysis Tool with Real-Time Progress")
root.geometry("800x600")
root.configure(bg="#f0f8ff")

header = tk.Label(root, text="Ransomware Analysis Tool", bg="#4682b4", fg="white", font=("Arial", 18))
header.pack(fill=tk.X, pady=10)

description = tk.Label(root, text="Select the directory to analyze:", bg="#f0f8ff", font=("Arial", 12))
description.pack(pady=10)

path_frame = tk.Frame(root, bg="#f0f8ff")
path_frame.pack(pady=5)

path_entry = tk.Entry(path_frame, width=50)
path_entry.pack(side=tk.LEFT, padx=5)

browse_button = tk.Button(path_frame, text="Browse", bg="#4682b4", fg="white", font=("Arial", 10), command=select_directory)
browse_button.pack(side=tk.LEFT)

start_button = tk.Button(root, text="Start Analysis", bg="#32cd32", fg="white", font=("Arial", 12), command=start_analysis)
start_button.pack(pady=10)

log_label = tk.Label(root, text="Analysis Log:", bg="#f0f8ff", font=("Arial", 12))
log_label.pack(pady=5)

log_textbox = tk.Text(root, height=20, width=95, state=tk.NORMAL, bg="#ffffff", fg="#000000", font=("Courier", 10))
log_textbox.pack(pady=5)

save_button = tk.Button(root, text="Save Report", bg="#4682b4", fg="white", font=("Arial", 12), command=save_report)
save_button.pack(pady=10)

quit_button = tk.Button(root, text="Quit", bg="#ff6347", fg="white", font=("Arial", 12), command=root.quit)
quit_button.pack(pady=10)

tool = RansomwareAnalysisTool(log_message)

root.mainloop()
