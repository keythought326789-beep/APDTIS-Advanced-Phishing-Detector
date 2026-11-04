
# APDTIS V5
### Advanced Phishing & Threat Intelligence System

APDTIS is a Python-based cybersecurity tool designed to perform preliminary phishing analysis and threat intelligence checks on URLs and email messages.

It combines local heuristic analysis, DNS resolution, and VirusTotal threat intelligence to generate a security report.

## Features

- URL normalization and validation
- Suspicious URL keyword detection
- IP address and domain analysis
- DNS resolution
- Email address extraction
- Phishing-language detection
- Email link extraction and analysis
- VirusTotal URL intelligence
- VirusTotal domain reputation checks
- Risk classification
- Security report generation
- Error handling for API and network issues

## Technologies Used

- Python
- Requests
- Regular Expressions
- Socket / DNS
- VirusTotal API v3

## Project Structure

```text
APDTIS-Advanced-Phishing-Detector/
├── APDTIS.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

### 1. Install Python

Download Python from:

https://www.python.org/downloads/

### 2. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/APDTIS-Advanced-Phishing-Detector.git
```

### 3. Navigate to the project directory

```bash
cd APDTIS-Advanced-Phishing-Detector
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

## VirusTotal API Configuration

APDTIS uses the VirusTotal API for threat intelligence.

1. Create an account at https://www.virustotal.com/
2. Obtain your API key from your VirusTotal account.
3. Configure the API key as an environment variable.

### Windows CMD

```cmd
setx VT_API_KEY "YOUR_VIRUSTOTAL_API_KEY"
```

Close and reopen the terminal after setting the variable.

**Security:** Never hardcode or publish your API key. Never commit secrets to GitHub.

## Usage

Run the program:

```bash
python APDTIS.py
```

Enter a URL, email address, or email message when prompted.

Type `EXIT` to close the program.

## Risk Assessment

APDTIS combines local heuristic indicators with available VirusTotal intelligence.

Possible assessments include:

- LOW RISK
- MEDIUM RISK
- HIGH RISK
- MALICIOUS
- INCONCLUSIVE

An inconclusive assessment means sufficient threat intelligence was not available.

## Limitations

- Heuristic analysis may produce false positives or false negatives.
- VirusTotal results depend on available reports and API access.
- Existing reports do not guarantee a fresh scan.
- A low-risk result does not guarantee that a URL or email is safe.
- This tool is intended for educational and defensive cybersecurity purposes.

## Disclaimer

APDTIS is an educational cybersecurity project intended for authorized defensive analysis.

The developer is not responsible for misuse of this tool.

## Author

Cybersecurity Learner | Python Security Projects
