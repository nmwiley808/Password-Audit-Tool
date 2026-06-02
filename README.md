# Password Audit Tool

A cybersecurity CLI tool and Google Colab notebook for auditing passwords
for strength, breach exposure, and dangerous structural vulnerabilities.

Built with `zxcvbn`, `rich`, `requests`, `hashlib`, and `click`.

---

## Demo

![audit demo](demo.png)

---

## Features

| Feature | Description |
|---|---|
| Strength scoring | Realistic crack-time estimation via `zxcvbn` — not just length/complexity rules |
| Breach detection | k-anonymity SHA1 lookup via HaveIBeenPwned — password never leaves your machine |
| Pattern detection | Flags keyboard walks, dates, repeated chars, and l33tspeak substitutions |
| Color-coded report | Green / amber / red Rich table output in the terminal |
| Bulk audit | Audit an entire `.txt` file of passwords in one command |
| CSV export | Save a full audit report as a shareable spreadsheet |
| CLI interface | Portable `audit.py` script with `--flags` and `--help` via `click` |

---

## Quickstart

```bash
# Install dependencies
pip install zxcvbn rich requests click

# Check a single password
python audit.py check "mypassword"

# Bulk audit a password list
python audit.py bulk passwords.txt

# Bulk audit and export results to CSV
python audit.py bulk passwords.txt --output report.csv

# Skip HIBP breach check (offline mode)
python audit.py check "mypassword" --no-hibp
```

---

## Project Structure
