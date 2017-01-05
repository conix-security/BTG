# BTG
![BTG with TOR IP](http://pix.toile-libre.org/upload/original/1482330236.png)

This tool allows you to qualify one or more potential malicious markers of different type (URL, MD5, SHA1, SHA256, SHA512, IPv4, IPv6, domain etc..). You can run this tool with a Gnu/Linux environement. The Windows compatibility is currently working in BETA version.

BTG was born from a need for Conix's collaborators. During their activities, SOC and DFIR analysts have to face off a lot of information and metadatas of multiple nature that they must identify as malicious or not.

Many knowledge-bases of malicious known activity (aka [IOC](https://en.wikipedia.org/wiki/Indicator_of_compromise)) are accessible online on various website like [VirusTotal](https://virustotal.com), [ZeusTracker](https://zeustracker.abuse.ch) etc. SOC and CERT can also have their own internal database such as [MISP](http://www.misp-project.org).

**Daily tasks for SOC and DFIR analysts is therefore marked out by the research of data like IP addresses, hashs, domains; on these private or public knowledge-bases; these are repetitive and time-consuming actions.**

Thus CERT-Conix created a tool allowing analysts to qualify such elements searchling many sources.

[![asciicast](https://asciinema.org/a/04a88eeh3rt0v979cxiuk8kzc.png)](https://asciinema.org/a/04a88eeh3rt0v979cxiuk8kzc)


#### Module list:
    DShield
    Lehigh
    Malekal
    Malwaredomains
    Malwaredomainlist
    MalwareTeks
    MISP (Malware Information Sharing Platform)
    Noeuds de sortie Tor
    OpenPhish
    Palevo
    VirusTotal
    ZeusTracker

#### Installation
```
sudo pip install -r requirements
cp config.py.editme config.py
vim config.py 
```
Activate and fill licence key for modules you need to use.

#### Usage:
```
python BTG.py http://mydomain.com 1a72dca1f6a961f528007ef04b6959d8 45.34.191.173
```
