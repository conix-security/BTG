# BTG

Not every IOC deserve to enter your internal MISP instance, for obvious quality reasons. But it may be usefull for you analyst to be able to do a broader research on IOC published online.

![BTG with TOR IP](http://pix.toile-libre.org/upload/original/1482330236.png)

This tool allows you to qualify one or more potential malicious observables of various type (URL, MD5, SHA1, SHA256, SHA512, IPv4, IPv6, domain etc..). You can run this tool with a Gnu/Linux environement. The Windows compatibility is currently working in BETA version.

BTG was born from a need for Conix's collaborators. During their activities, SOC and DFIR analysts face off a lot of information and metadata of multiple nature that they must classify as malicious or not.

Many knowledge-bases of malicious known activity (aka [IOC](https://en.wikipedia.org/wiki/Indicator_of_compromise)) are accessible online on various website like [VirusTotal](https://virustotal.com), [ZeusTracker](https://zeustracker.abuse.ch) etc. SOC and CERT can also have their own internal database such as [MISP](http://www.misp-project.org).

**Daily tasks for SOC and DFIR analysts is therefore marked out by the research of data like IP addresses, hashs, domains; on these private or public knowledge-bases; these are repetitive and time-consuming actions.**

Thus CERT-Conix created a tool allowing analysts to qualify such elements searching many sources.

[![asciicast](https://asciinema.org/a/04a88eeh3rt0v979cxiuk8kzc.png)](https://asciinema.org/a/04a88eeh3rt0v979cxiuk8kzc)


#### Module list:
    CuckooSandbox API
    Cybercrime-tracker
    DShield
    Lehigh
    Malekal
    Malshare
    Malwaredomainlist
    Malwaredomains
    MalwareTeks
    MISP (Malware Information Sharing Platform)
    MISP Crawler
    Nothink
    OpenPhish
    OTX
    RansomwareTracker
    SpamHaus
    SSLBlacklist
    Tor exit nodes
    VirusTotal
    Vxvault
    ZeusTracker

#### Adding your module
```
cp modules/template.module modules/yourModuleName.py
vim modules/yourModuleName.py
```
Change every CHANGEME in the template
Then polulate the __init__ method with basic information and fill search() method with the logic needed to check self.ioc against the data provided by your database (basic logic is provided to guide you). Call to display() must be done to print results prettily.

#### Installation
```
sudo pip install -r requirements.txt
cp config.ini.editme config.ini
vim config.ini
```
Activate and fill licence key for modules you need to use.

#### Usage
```
python BTG.py http://mydomain.com 1a72dca1f6a961f528007ef04b6959d8 45.34.191.173
```

#### Authors
- Lancelot Bogard
- Robin Marsollier
