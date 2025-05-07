# SecuScanner 🔍

> ⚠️ **Disclaimer**: This tool is intended for educational and ethical cybersecurity purposes only. The developer (**SecuHari**) is not responsible for any misuse or illegal activity carried out using this tool.

**SecuScanner** is a hacker-style CLI tool for scanning websites and identifying exposed API keys, tokens, and sensitive data.


## 🚀 Features

- Detects AWS, Google, Stripe, and generic secrets
- Cool terminal banner and color-coded output
- Accepts single URL or list of URLs from file
- JSON export support
- Save scan results to file

## 🛠 Installation

```bash

git clone https://github.com/SecuHari/SecuScanner.git
cd SecuScanner
pip install -r requirements.txt

```

## 💡 Usage

```bash
# Scan single URL
python3 scanner.py --url https://example.com

# Scan multiple URLs from file
python3 scanner.py --list urls.txt

# Output to JSON and save to file
python3 scanner.py --url https://example.com --json --output result.json
```

## 👨‍💻 License

MIT License
