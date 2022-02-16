#!/usr/bin/python3
import requests
import pandas as pd
import sys
from configobj import ConfigObj
import os.path
import time
import argparse

option = sys.argv[1]
argument = sys.argv[2]
env = '100'

pd.set_option('display.max_rows', 1000)
pd.set_option('display.max_columns', 1000)
pd.set_option('display.width', 1000)
pd.set_option('max_colwidth', 1000)

parser = argparse.ArgumentParser(description='Query information about malware by hash, IP address, URL, and File send to sandbox')
parser.add_argument('-H','--hash', help="SHA256 hash of malware file" )
parser.add_argument('-I','--ip', help="IPv4 address" )
parser.add_argument('-F','--file', help="Path for file upload to sandbox" )

def json_extract(obj, key):
    """Recursively fetch values from nested JSON."""
    arr = []
    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        try:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        extract(v, arr, key)
                    elif k == key:
                        arr.append(v)
            elif isinstance(obj, list):
                for item in obj:
                    extract(item, arr, key)
            return arr
        except Exception as e:
            print('[DEBUG] Failed parse J')
    values = extract(obj, arr, key)
    return values

def check(option):
    if (option == '-I'):
     ip_result=virustotal_ip(argument)
     return(ip_result)
    elif (option == '-H'):
     if(len(argument)==64):
         hash_result_vt=virustotal_hash(argument)
         hash_result_ha=hybrid_analyser_hash(argument)
         hash_result_mb=malbazaarlookup(argument)
         return(hash_result_vt,hash_result_ha,hash_result_mb)
     else: print('\n[DEBUG] Entered invalid sha256 hash\n')
     sys.exit()
    elif (option == '-F'):
     env=sys.argv[3]
     correct_checker(env)
     sandbox_chk = hybrid_analysis_sandbox(argument,env)
     return(sandbox_chk)
    elif sys.argv < 1:
     print('[DEBUG] Entered incorrect argument!!!\nExample: <progname> <-I/-H/-F> <ip/hash/filepath>')
    else: print('[DEBUG] Entered incorrect argument!!!\nExample: <progname> <-I/-H/-F> <ip/hash/filepath>')
        
def correct_checker(env):
    if(env!='100') and (env!='110') and (env!='120') and (env!='200') and (env!='300'):
             print("[DEBUG] Error you entered incorrect ENVIROMENT_ID!!!")
             print("[DEBUG] Enter correct ENVIROMENT_ID:\n 100 OR 110 OR 120 OR 200 OR 300")
             print("[DEBUG] 100 - means 'Windows 7 32 bit'\n 110 - means 'Windows 7 32 bit (HWP Support)'\n 120 - means 'Windows 7 64 bit'\n 200 - means 'Android Static Analysis'\n 300 - Linux (Ubuntu 16.04, 64 bit)\n")
             sys.exit()

def virustotal_ip(argument):
    try:
        params = {'apikey':vt_api,'ip':argument}
        response = requests.get(ip_vt, params=params)
        value = response.json()
        hostname = json_extract(value, 'hostname')
        last_resolved = json_extract(value, 'last_resolved')
        hostname = pd.DataFrame({"Hostname": hostname, "Last_resolved" : last_resolved})
        return(hostname)
    except Exception as e:
        print("[DEBUG] Failed send IP to Virus Total\n")

def virustotal_hash(argument):
    try:
        params = {'apikey':vt_api,'resource':argument}
        response = requests.get(url_vt, params=params)
        value = response.json()
        print('\t\t\t\t\t\t\t\t===============================Virus_Total_Report===============================\n\n')
        total = pd.DataFrame({'Name':['permalink','positives','scan_date','sha256','total','verbose_msg'],'Value':[value['permalink'], value['positives'], value['scan_date'], value['sha256'], value['total'],value['verbose_msg']]})
        print(total)
    except Exception as e:
        print('\t\t\t\t\t\t\t\t===============================Virus_Total_Report===============================\n\n')
        print("[DEBUG] Failed send SHA256 hash to Virus Total\n",e)

def hybrid_analyser_hash(argument):
    try:
        headers = {
        'accept': 'application/json',
        'user-agent': 'Falcon Sandbox',
        'Content-Type': 'application/x-www-form-urlencoded',
        'api-key': ha_api,}
        data = {'hash': argument}
        response = requests.post(ha_hash, headers=headers, data=data)
        value = response.json()
        attck_id = json_extract(value,'attck_id')
        attck_id_wiki = json_extract(value,'attck_id_wiki')
        enviroment_OS = json_extract(value, 'environment_description')
        tags = json_extract(value, 'tags')
        types = json_extract(value, 'type')
        virus_family = json_extract(value, 'vx_family')
        total = pd.DataFrame({"Mitre_Attack_ID": attck_id,"Mitre_Attack_Link":attck_id_wiki})
        total_t = pd.DataFrame({"Enviroment_OS":enviroment_OS,"Type of Malware": types})
        m_tags = pd.DataFrame({"Malware Tags":tags})
        la_malware_familia = pd.DataFrame({"Virus_family/subfamily":virus_family})
        totality = pd.concat([total,total_t,la_malware_familia],ignore_index=False,axis=1)
        print('\n\n\t\t\t\t\t\t\t\t===============================Hybrid_Analyze_Report===============================\n\n')
        print(totality)
        for key in value:
            for j in key:
                if(j=='domains'):
                    if(key[j]==[]):
                        break
                    else:
                        print(j,key[j])
    except Exception as e:
        print('\n\n\t\t\t\t\t\t\t\t===============================Hybrid_Analyze_Report===============================\n\n')
        print("[DEBUG] Failed send Hash to Hybrid Analysis\n")

def malbazaarlookup(hash):    
    data = {'query': 'get_info', 'hash': hash}
    url = "https://mb-api.abuse.ch/api/v1/"
    try:
        response = requests.post(url, data=data,verify=False)
        value = response.json()['data'][0]

        print('\n\n\t\t\t\t\t\t\t\t===============================Malware Bazaar===============================\n\n')
        keyslist=[]
        for key in value.keys():
            keyslist.append(key)

        if 'vendor_intel' in keyslist:
            intel = value.get('vendor_intel')
            print('Vendor_INTEL:\n')
            if 'filescan' in intel:
                print(intel.keys())
                filescan = intel.get('FileScan-IO')
                verdict = filescan.get('verdict')
                report_lnk = filescan.get('report_link')
                print('\nVerdict\n', verdict)
                print('\nReport link\n', report_lnk)
                print('\nDelivery method:\n', value.get('delivery_method'))
            if 'ANY.RUN' in intel:
                print('\nANY.RUN sandbox information:',intel.get('ANY.RUN'))
            if 'CERT-PL_MWDB' in intel:
                print('\nCERT-PL_MWDB information:',intel.get('CERT-PL_MWDB'))
            if 'YOROI_YOMI' in intel:
                print('\nYOROI_YOMI information', intel.get('YOROI_YOMI'))
            if 'Intezer' in intel:
                print('\nIntezer information',intel.get('Intezer'))
            if 'InQuest' in intel:
                print('\nInQuest information',intel.get('InQuest'))
            if 'CAPE' in intel:
                print('\nCAPE information',intel.get('CAPE'))
            # if 'Triage' in intel:
                #print('\nTriage information',intel.get('Triage'))
            if 'ReversingLabs' in intel:
                print('\nReversingLabs information' ,intel.get('ReversingLabs'))
            if 'Spamhaus_HBL' in intel:
                print('\nSpamhaus_HBL information',intel.get('Spamhaus_HBL'))
            if 'UnpacMe' in intel:
                print('\nUnpacMe information',intel.get('UnpacMe'))
        if 'file_name' in keyslist:
            print('\nFile name:', value.get('file_name'))
        if 'file_type_mime' in keyslist:
            print('\nFile type is:', value.get('file_type_mime'))
            if 'file_type' in keyslist:
                print(value.get('file_type'))
        if 'tags' in keyslist:
            print('\nTags',value.get('tags'))
        if 'delivery_method' in keyslist:
            print('\nDelivery Method',value.get('delivery_method'))
        if 'intelligence' in keyslist:
            print('\nIntelligence:',value.get('intelligence'))
        if 'file_information' in keyslist:
            if 'value' in keyslist.get('file_information'):
                print('\nFile information link:',value.get('value'))
        
        
    except Exception as e:
        print('\n\n\t\t\t\t\t\t\t\t===============================Malware Bazaar===============================!\n\n')
        #print(value)
        print('[DEBUG] Cannot to send request, check your internet connection!!!',e)




def hybrid_analysis_sandbox(filepath, env):
    headers = {
    'accept': 'application/json',
    'user-agent': 'Falcon Sandbox',
    'api-key': ha_api,
}
    f = open(r'{}'.format(filepath),'rb')
    files = {'file': (os.path.basename(r'{}'.format(filepath)), f), 'environment_id': (None, env)}
    response = requests.post(ha_sandbox, headers=headers, files=files)
    value = response.json()
    global ha_val 
    print(value)
    global ha_hash 
    ha_hash= value['sha256']


    if response.ok:
        print('[DEBUG] File was ulpoaded to Falcon Sandbox')
        print('job_id:',value['job_id'])
        print(value)
        print('environment_id:',value['environment_id'])
        print('sha256:',value['sha256'])
    else:
        print('Operation Failed.')
    time.sleep(10)
    hybrid_analyser_submitted_info(ha_hash)
        
def hybrid_analyser_submitted_info(ha_hash):
    try:    
        headers = {
        'accept': 'application/json',
        'user-agent': 'Falcon Sandbox',
        'api-key': ha_api,
    }
        data = {
    'hashes[]': ha_hash,
    }   
        ha_summary = 'https://www.hybrid-analysis.com/api/v2/report/summary'
        response = requests.post(ha_summary, headers=headers, data=data)
        res = response.json()
        print('\n\n\t\t\t\t\t\t\t\t===============================Information From Sandbox===============================n\n')
        print(res)
        return(ha_hash)
    except Exception as e:
        print("[DEBUG] Failed upload File to Hybrid Analysis\n")



config = ConfigObj('config.ini')

vt_section = config['VT']
vt_api = vt_section['VT_API']
ip_vt = vt_section['IPFIND_URL']
url_vt = vt_section['HASHFIND_URL']

ha_section = config['HA']
ha_api = ha_section['HA_API']
ha_hash = ha_section['HASHFIND_URL']
ha_sandbox = ha_section['URLFIND_URL']
ha_summary = ha_section['URLSUM_URL']

print (check(option))
