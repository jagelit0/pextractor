<h3 align="center">Pextractor</h3>
<p align="center">Python3 script to extract information about PEs using <a href="https://github.com/erocarrera/pefile">pefile</a> library</p>

# Required libraries
```
pip3 install peutils pefile hashlib math argparse
```

# Usage
```
usage: pextract.py [-h] [-t TARGET] [-s] [-i] [-e] [-x] [-dh] [-nh] [-vt]

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Select PE file to scan
  -s, --sections        Extract sections
  -i, --imports         Extract imported DLLs
  -e, --exports         Extract exported Symbols
  -x, --extract-all     Extract all Headers
  -dh, --dos-header     Extract DOS Header
  -nh, --nt-header      Extract File Header
  -vt, --virus-total    Search hash in VirusTotal
```
