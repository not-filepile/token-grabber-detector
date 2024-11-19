
# Discord-Grabber-Detector

## How it Works
The Discord-Grabber-Detector utilizes a combination of Go or Python to detect and mitigate malicious code that attempts to steal Discord tokens. The tool examines executables and scripts to identify patterns and behaviors associated with token grabbers. It leverages the capabilities of the `strings` command, pyinstxtractor-go, and the OpenAI API for extracting and analyzing Python executables.

### Key Features
- **Extraction**: Utilizes the `strings` command and pyinstxtractor-go to extract Python bytecode from compiled executables.
- **Analysis**: Scans extracted files for known patterns and signatures of Discord token grabbers using OpenAI's API.
- **Reporting**: Provides detailed reports on any identified threats, allowing for easy review and remediation.

## Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/not-filepile/Discord-Grabber-Detector.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Discord-Grabber-Detector
   ```
3. Run the detector (choose between Python and Go):
   ```bash
   # For Go
   go run main.go

# TODO
- add analyze for various type of malicious code
- web support
- discord bot support

## Decompiler from
[pyinstxtractor-go](https://github.com/pyinstxtractor/pyinstxtractor-go)

   # For Python
   python main.py
   ```

## Contributing
Feel free to contribute by opening issues or submitting pull requests.
