# MalRipper

Find Malware in global database like VirusTotal, Hybrid Analysis etc.

Script allow to find Malware by Hash, IP-address and to upload malicious file to Hybrid Analysis Sandbox.

For search information by File Hash use ./MalRipper.py -H <Sha256>
  
As we can see there are Mitre Attack Martix for malware hash and report by VirusTotal about posistives scan.
  
  ![MalRipper Hash](https://user-images.githubusercontent.com/97513066/149723825-653ebbe0-2547-43d0-a195-eddfd4903007.jpg)

For search information by IP-address use ./MalRipper.py -I <IP>
  
![MalRipper_IP](https://user-images.githubusercontent.com/97513066/149723976-873df511-d53f-4acc-b3ff-064d802d62e9.JPG)
  
You can parse this.

For upload file to Hybrid Analysis Sandbox and get report from, use ./MalRipper.py -F <filepath> <300 or 200 or 100>
