# Virus Total Scanner

This script recursively scans through a user specified directory and submits 
sha256 hashes of the files discovered to Virus Total.  The results from
Virus Total are displayed to the user and saved into a dictionary.  The dictionary
is persistent across scans and files that are already identified are not submitted
to Virus Total again.  For files that haven't been scanned by Virus Total,
the user has the option of writing YARA rules that will run against those files.

## Requirements:

- Python 3
    - queue
    - multiprocessing
    - time
    - json
    - hashlib
    - os
    - sys
    - argparse
    - requests
    - configparser
    - yara-python
    
- YARA v3.9.0
    - [YARA](https://virustotal.github.io/yara/)

## Installation instructions

- Install Python 3
    - Most of the packages used are standard so you shouldn't need to install many extra ones.

- Install python3-pip

- Build and install YARA
    - [Instructions](https://yara.readthedocs.io/en/v3.4.0/gettingstarted.html)
    - On Ubuntu 18.04 you will need at least `build-essential`, `autoconf`, `libssl-dev`, and `libtool`

- Install yara-python
    - pip3 install yara-python

## Usage

- Configuration
    - The VirusTotal API key as well as important file locations are set in `scanner_config.ini`
    - There is initially no hash dictionary file, it will be created as the first scan is run.

- YARA Rules
    - To learn how to write additional YARA rules see [Writing YARA Rules](https://yara.readthedocs.io/en/v3.8.1/writingrules.html)
    - Alternatively, you can use rules that are publically available and look for common malware.

- Help Menu
    - To see the list of available commands, run `python3 scanner.py --help`

## Example
This repository contains a test directory that has a few binaries and text files to scan.  The scanner is currently 
using the public VirusTotal API and is therefore limited to 4 requests per minute.  

To scan the example directory, run the following command from the `/vt_scanner/src` directory:

`python3 scanner.py ../test_directory/`