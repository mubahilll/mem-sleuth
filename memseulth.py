import re
import argparse
import os
import math

RED = "\33[91m"
BLUE = "\33[94m"
GREEN = "\033[32m"
YELLOW = "\033[93m"
PURPLE = '\033[0;35m' 
CYAN = "\033[36m"
END = "\033[0m"

banner = f""" {RED}
  __  __                   _____ _            _   _     
 |  \/  |                 / ____| |          | | | |    
 | \  / | ___ _ __ ___   | (___ | | ___ _   _| |_| |__  
 | |\/| |/ _ \ '_ ` _ \   \___ \| |/ _ \ | | | __| '_ \ 
 | |  | |  __/ | | | | |  ____) | |  __/ |_| | |_| | | |
 |_|  |_|\___|_| |_| |_| |_____/|_|\___|\__,_|\__|_| |_|\n
 {RED} High                   {YELLOW}Moderate                   {GREEN}Low
 {END}
 
"""

def search_patterns(memory_data, patterns):
    findings = []
    for pattern in patterns:
        if re.search(pattern, memory_data):
            findings.append(f"Suspicious pattern detected: {pattern.decode('utf-8')}")
    return findings

def extract_ascii_strings(memory_data, min_length=4):
    strings = re.findall(b'[ -~]{' + str(min_length).encode() + b',}', memory_data)
    return [string.decode('utf-8') for string in strings]

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def entropy_category(entropy_value):
    if entropy_value < 5:
        return "\033[92mLow\033[0m"     # Green for low entropy
    elif 5 <= entropy_value < 7:
        return "\033[93mModerate\033[0m" # Yellow for moderate entropy
    else:
        return "\033[91mHigh\033[0m"     # Red for high entropy

def segment_memory_dump(memory_data, segment_size=1024*1024):
    return [memory_data[i:i+segment_size] for i in range(0, len(memory_data), segment_size)]

def analyze_memory_dump(memory_dump_path):
    findings = []
    if not os.path.isfile(memory_dump_path):
        return [f"Memory dump file not found: {memory_dump_path}"]

    patterns = [b"malware_signature", b"unauthorized_access", b"\\x90\\x90\\x90"]
    try:
        with open(memory_dump_path, 'rb') as file:
            memory_data = file.read()

        findings.extend(search_patterns(memory_data, patterns))

        ascii_strings = extract_ascii_strings(memory_data)
        findings.append(f"Extracted ASCII strings: {', '.join(ascii_strings[:10])}...")

        entropy = calculate_entropy(memory_data)
        entropy_cat = entropy_category(entropy)
        findings.append(f"Calculated entropy: {entropy_cat} ({entropy:.2f})")

        for i, segment in enumerate(segment_memory_dump(memory_data)):
            segment_entropy = calculate_entropy(segment)
            segment_cat = entropy_category(segment_entropy)
            findings.append(f"Entropy of segment {i}: {segment_cat} ({segment_entropy:.2f})")

    except Exception as e:
        findings.append(f"Error processing file: {e}")

    return findings

def generate_report(findings):
    return "Analysis Report:\n" + "\n".join(findings)

def main():
    parser = argparse.ArgumentParser(description='Enhanced Memory Forensics Script')
    parser.add_argument('memory_dump_path', type=str, help='Path to the memory dump file')
    args = parser.parse_args()

    analysis_results = analyze_memory_dump(args.memory_dump_path)
    report = generate_report(analysis_results)
    
    print(report)

if __name__ == "__main__":
    print(banner)
    main()
