# AnyPwn 

Pwn any Anyconnect (except those patched). 

This repo summarizes the fun I had playing with Cisco Anyconnect VPN Mobility Client. It's more like a framework to craft
malicious CIPC messages and fuzz the `vpnservice.exe`. Hope to get back to this one day.

My take on CVE-2020-3153 implements a slight difference in payload to evade Symantec HIPS.

Exploits implemented so far:
1. [CVE-2017-6638](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-anyconnect) 
2. [CVE-2020-3153](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-anyconnect-dll-F26WwJW) - Fixed in `4.8.02042`

Tested on:
* 4.2 (CVE-2017-6638)
* 4.5.03040 (CVE-2020-3153)
* 4.6.03049 (CVE-2020-3153)
* 4.7.01076 (CVE-2020-3153)

## Usage

1. Make sure requirements are met - `python3 -m pip install -r requirements.txt`
2. Pwn `python3 main.py <optional command to run>` - runing it without argument will exploit the vulnerability but won't place `dbghelp.dll` and cause code execution via dll hijacking. 
