#!/bin/python3
import re
import os
import numpy as np
import concurrent.futures
import mmap
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter.ttk import Progressbar, Style, Button, Label, Frame
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
import threading

# Memory Analysis Functions
def search_patterns(memory_data, patterns):
    """Search for patterns in memory data."""
    findings = []
    for pattern in patterns:
        if re.search(pattern, memory_data):
            findings.append(f"Suspicious pattern detected: {pattern.decode('utf-8')}")
    return findings

def extract_ascii_strings(memory_data, min_length=4):
    """Extract ASCII strings from memory data."""
    strings = re.findall(b'[ -~]{' + str(min_length).encode() + b',}', memory_data)
    return [string.decode('utf-8') for string in strings]

def calculate_entropy(data):
    """Calculate the entropy of a data segment."""
    if len(data) == 0:
        return 0
    data = np.frombuffer(data, dtype=np.uint8)
    prob = np.bincount(data) / len(data)
    prob = prob[prob > 0]
    return -np.sum(prob * np.log2(prob))

def entropy_category(entropy_value):
    """Categorize entropy levels."""
    if entropy_value < 5:
        return "Low"
    elif 5 <= entropy_value < 7:
        return "Moderate"
    else:
        return "High"

def segment_memory_dump(memory_data, segment_size=512*1024):
    """Segment the memory data into chunks."""
    return [memory_data[i:i+segment_size] for i in range(0, len(memory_data), segment_size)]

def analyze_memory_dump(memory_dump_path, progress_callback=None):
    """Analyze the memory dump for suspicious patterns and entropy."""
    findings = []
    if not os.path.isfile(memory_dump_path):
        return [f"Memory dump file not found: {memory_dump_path}"]

    patterns = [b"malware_signature", b"unauthorized_access", b"\\x90\\x90\\x90"]

    try:
        with open(memory_dump_path, 'rb') as file:
            with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as memory_data:
                findings.extend(search_patterns(memory_data, patterns))
                ascii_strings = extract_ascii_strings(memory_data)
                findings.append(f"Extracted ASCII strings: {', '.join(ascii_strings[:10])}...")

                segments = segment_memory_dump(memory_data)

                # Calculate entropy concurrently with progress updates
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    futures = {executor.submit(calculate_entropy, seg): i for i, seg in enumerate(segments)}
                    for i, future in enumerate(concurrent.futures.as_completed(futures)):
                        entropy = future.result()
                        category = entropy_category(entropy)
                        findings.append(f"Entropy of segment {futures[future]}: {category} ({entropy:.2f})")
                        if progress_callback:
                            progress_callback((i + 1) / len(segments) * 100)  # Update progress

    except Exception as e:
        findings.append(f"Error processing file: {e}")

    return findings

def generate_report(findings):
    """Generate a textual report from findings."""
    return "Analysis Report:\n" + "\n".join(findings)

# GUI Class
class MemoryForensicsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MemSleuth")
        self.root.geometry("800x700")
        self.root.configure(bg='#1b3a57')  # Navy blue background

        self.setup_styles()
        self.create_widgets()
        self.report_text = ""

    def setup_styles(self):
        """Setup custom styles for the GUI."""
        self.style = Style()
        self.style.theme_use('clam')  # Modern look
        self.style.configure('TButton', font=('Helvetica', 10), background='#ffffff', foreground='#1b3a57', padding=5)
        self.style.map('TButton', background=[('active', '#f0f0f0')])  # Hover effect with slight change
        self.style.configure('TLabel', font=('Helvetica', 12), background='#1b3a57', foreground='#ffffff', padding=5)
        self.style.configure('TFrame', background='#1b3a57')
        self.style.configure('TProgressbar', thickness=20, troughcolor='#1b3a57', background='#ffffff')

    def create_widgets(self):
        """Create and layout the widgets in the GUI."""
        # Header
        self.header = Label(self.root, text="Memory Forensics Analyzer", style='TLabel', font=('Helvetica', 16, 'bold'))
        self.header.pack(pady=10)

        # Frames for layout
        self.file_frame = Frame(self.root, style='TFrame')
        self.file_frame.pack(pady=10)

        self.button_frame = Frame(self.root, style='TFrame')
        self.button_frame.pack(pady=10)

        self.output_frame = Frame(self.root, style='TFrame')
        self.output_frame.pack(pady=10)

        # File selection
        self.file_label = Label(self.file_frame, text="Memory Dump File:", style='TLabel')
        self.file_label.grid(row=0, column=0, padx=5)

        self.file_entry = tk.Entry(self.file_frame, width=50, bg='#ffffff', fg='#1b3a57')
        self.file_entry.grid(row=0, column=1, padx=5)

        self.browse_button = Button(self.file_frame, text="Browse", command=self.browse_file, style='TButton')
        self.browse_button.grid(row=0, column=2, padx=5)

        # Analysis buttons
        self.analyze_button = Button(self.button_frame, text="Start Analysis", command=self.start_analysis, style='TButton')
        self.analyze_button.grid(row=0, column=0, padx=10)

        self.save_pdf_button = Button(self.button_frame, text="Export to PDF", command=self.export_to_pdf, style='TButton')
        self.save_pdf_button.grid(row=0, column=1, padx=10)

        # Progress bar
        self.progress_bar = Progressbar(self.root, orient='horizontal', mode='determinate', length=600, style='TProgressbar')
        self.progress_bar.pack(pady=20)

        # Text area for output
        self.output_text = scrolledtext.ScrolledText(self.output_frame, width=90, height=20, wrap=tk.WORD, bg='#ffffff', fg='#1b3a57', font=('Helvetica', 10))
        self.output_text.pack(pady=10)

    def browse_file(self):
        """Open a file dialog to select a memory dump file."""
        file_path = filedialog.askopenfilename(
            title="Select Memory Dump File",
            filetypes=[("Memory Dumps", "*.dmp *.bin" "*.raw"), ("All Files", "*.*")]
        )
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)

    def start_analysis(self):
        """Start the memory dump analysis in a separate thread."""
        file_path = self.file_entry.get()
        if not file_path:
            messagebox.showwarning("Warning", "Please select a memory dump file!")
            return

        # Clear the previous output and reset progress bar
        self.output_text.delete(1.0, tk.END)
        self.progress_bar['value'] = 0

        # Start analysis in a new thread
        analysis_thread = threading.Thread(target=self.run_analysis, args=(file_path,))
        analysis_thread.start()

    def run_analysis(self, file_path):
        """Run the analysis and update the GUI."""
        self.output_text.insert(tk.END, "Analyzing...\n")
        self.root.update_idletasks()

        findings = analyze_memory_dump(file_path, progress_callback=self.update_progress)
        report = generate_report(findings)

        # Display the results
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, report)
        self.report_text = report

    def update_progress(self, value):
        """Update the progress bar."""
        self.progress_bar['value'] = value
        self.root.update_idletasks()

    def export_to_pdf(self):
        """Export the analysis report to a PDF file."""
        if not self.report_text:
            messagebox.showwarning("Warning", "No analysis report to export!")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All Files", "*.*")],
            title="Save Report As"
        )
        if not file_path:
            return

        self.create_pdf_report(file_path)
        messagebox.showinfo("Success", f"Report saved to {file_path}")

    def create_pdf_report(self, file_path):
        """Create and save a PDF report from the analysis findings."""
        doc = SimpleDocTemplate(file_path, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        low_style = ParagraphStyle('Low', parent=styles['Normal'], textColor=colors.green)
        moderate_style = ParagraphStyle('Moderate', parent=styles['Normal'], textColor=colors.orange)
        high_style = ParagraphStyle('High', parent=styles['Normal'], textColor=colors.red)

        for line in self.report_text.split("\n"):
            if "Low" in line:
                p = Paragraph(line, low_style)
            elif "Moderate" in line:
                p = Paragraph(line, moderate_style)
            elif "High" in line:
                p = Paragraph(line, high_style)
            else:
                p = Paragraph(line, styles['Normal'])
            elements.append(p)
            elements.append(Spacer(1, 12))

        doc.build(elements)

# Run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = MemoryForensicsGUI(root)
    root.mainloop()
