# Enhanced Memory Forensics Script
This is an enhanced memory forensics script designed to analyze memory dump files for suspicious patterns, ASCII strings, and entropy levels. It provides a detailed analysis report based on the findings.

## Features
- Search for suspicious patterns in memory dump files.
- Extract ASCII strings from memory dump files.
- Calculate entropy to assess randomness in the data.
- Segment memory dump files for more granular analysis.
- Generate an analysis report with all findings.
- **New**: GUI version for easy usage and is much faster than CLI script. Along you can save report into a pdf. 

## Prerequisites
- Python 3.x
- Required Python packages: `re`, `argparse`, `os`, `math`, `numpy`, `concurrent.futures`, `mmap`, `tkinter`, `reportlab`
## Usage

### Command-Line Version

1. Clone the repository:
```bash
git clone https://github.com/mubahilll/mem-seulth.git
```

2. Navigate to the directory:
```bash
cd mem-seulth
```

3. Run the script with the path to the memory dump file as an argument:
```bash
python3 enhanced_memory_forensics.py <memory_dump_path>
```
### GUI Version

1. Clone the repository:
```bash
git clone https://github.com/mubahilll/mem-seulth.git
```

2. Navigate to the directory:
```bash
cd mem-seulth
```

3. Run the script with the path to the memory dump file as an argument:
```bash
python3 memseulth-gui.py
```

## Output

The script generates an analysis report containing information about suspicious patterns, extracted ASCII strings, and entropy levels in the memory dump file.

## Contributors
- Ahsan Ahmed
  
## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
