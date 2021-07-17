<p align="center">
  <a href="https://example.com/">
    <img src="https://via.placeholder.com/72" alt="Logo" width=72 height=72>
  </a>

  <h3 align="center">IoC Miner</h3>

  <p align="center">
    A python tool that analyzes a supplied pcap file and attempts to collect all possible indicators of compromise and runs reputation checks. It generates an HTML incident report containing all possible malicious traffic and a list of IoCs found which saves time and provides a good starting point while working on an incident.
    <br>

## Usage syntax

```text
python iocminer.py test.pcap
```
## Requirements
  
### scapy
  ```text
pip install scapy
```
### requests
  ```text
pip install requests
```
### BeautifulSoup
  ```text
pip install beautifulsoup4
```
