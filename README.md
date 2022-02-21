# MalRipper

Find Malware in global databases like VirusTotal, Hybrid Analysis etc.

Script allow to find Malware by Hash, IP-address and to upload malicious file to Hybrid Analysis Sandbox.

For search information by File Hash use ./MalRipper.py -H Sha256
  
As we can see there are Mitre Attack Martix for malware hash and report by VirusTotal about posistives scan.
  
![image](https://user-images.githubusercontent.com/97513066/154960681-36cba4ee-5462-47da-99cf-10781b868f11.png)


For search information by IP-address use ./MalRipper.py -I IP
  
![MalRipper_IP](https://user-images.githubusercontent.com/97513066/149723976-873df511-d53f-4acc-b3ff-064d802d62e9.JPG)
  
You can parse this.

For upload file to Hybrid Analysis Sandbox and get report from, use ./MalRipper.py -F filepath 300/200/100 - where (100 - means 'Windows 7 32 bit'\n 110 - means 'Windows 7 32 bit (HWP Support)'\n 120 - means 'Windows 7 64 bit'\n 200 - means 'Android Static Analysis'\n 300 - Linux (Ubuntu 16.04, 64 bit))

![MalRipper_File](https://user-images.githubusercontent.com/97513066/149764804-fe5df5f1-d2a0-4930-bb21-163ec0e0bdab.JPG)
