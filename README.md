# vt-check
Small tool to query VirusTotal for files and IP addresses reputation.

## Installation
Use the following command to create a virtual environment and install the dependencies.
```
python3 -m venv vt_venv
source vt_venv/bin/activate
python -m pip install -r requirements.txt
```

## Configuration
You need to add your VirusTotal API key (and Proxy configuration if needed) in the 'config.json' file.
For that, you can just copy the 'config.json.template' to 'config.json' and complete the needed information in the new file.

## Usage
To check all the files in a directory:
```
python vt-check.py -d directory
```

To check a single file:
```
python vt-check.py -f sample.exe 
```

To check a list of hash:
(The parameter must be a text file with one hash per line, the hash can be of any algorithm)
```
python vt-check.py -l hash_list.txt
```

To check a list of IP addresses and get whois information:
(The parameter must be a text file with one IP address per line)
```
python vt-check.py -i ip_list.txt
```

## Info
When a file or IP address is reported as malicious by VirusTotal, its name (path) is written to the 'result.txt' file generated after execution of the script. More information on the scan(s) can be found in the generated 'info.log' file.
In case of IP addresses checking, the whois information are written to 'whois_results.csv'.

## TO-DO
* Improve whois information parsing
* Code cleaning
