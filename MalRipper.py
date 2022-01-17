import re
import requests
import pandas as pd
import sys
from configobj import ConfigObj
import os.path
import time

option = sys.argv[1]
argument = sys.argv[2]
env = '100'

pd.set_option('display.max_rows', 1000)
pd.set_option('display.max_columns', 1000)
pd.set_option('display.width', 1000)
pd.set_option('max_colwidth', 1000)


def json_extract(obj, key):
    """Recursively fetch values from nested JSON."""
    arr = []
    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
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
         return(hash_result_vt,hash_result_ha)
     else: print('\n[DEBUG] Entered invalid sha256 hash\n')
     sys.exit()
    elif (option == '-F'):
     env='300'
     correct_checker(env)
     sandbox_chk = hybrid_analyser_sandbox(argument,env)
     hash_result_vt=virustotal_hash(sandbox_chk)
     hash_result_ha=hybrid_analyser_hash(sandbox_chk)
     return(sandbox_chk,hash_result_vt,hash_result_ha)
    else:
     print('[DEBUG] Entered incorrect argument!!!\nExample: <progname> <-I/-H/-F> <ip/hash/filepath>')

def correct_checker(env):
    if(env!='100') and (env!='110') and (env!='120') and (env!='200') and (env!='300'):
             print("[DEBUG] Error you entered incorrect ENVIROMENT_ID!!!")
             print("[DEBUG] Enter correct ENVIROMENT_ID:\n 100 OR 110 OR 120 OR 200 OR 300")
             print("[DEBUG] 100 - means 'Windows 7 32 bit'\n 110 - means 'Windows 7 32 bit (HWP Support)'\n 120 - means 'Windows 7 64 bit'\n 200 - means 'Android Static Analysis'\n 300 - Linux (Ubuntu 16.04, 64 bit)\n")
             sys.exit()

def virustotal_ip(argument):
        params = {'apikey':vt_api,'ip':argument}
        response = requests.get(ip_vt, params=params)
        value = response.json()
        hostname = json_extract(value, 'hostname')
        last_resolved = json_extract(value, 'last_resolved')
        #positives = json_extract(value["detected_urls"],'positives')
        values = value
        print(values)
        for key in values:
                for j in key:
                    if(j=='positives'):
                        if(key[j]==[]):
                            break
                        else:
                            print(j,key[j])
        hostname = pd.DataFrame({"Hostname": hostname, "Last_resolved" : last_resolved})
        return(hostname)

def virustotal_hash(argument):
        params = {'apikey':vt_api,'resource':argument}
        response = requests.get(url_vt, params=params)
        value = response.json()
        print('\t\t\t\t\t\t\t\t===============================Virus_Total_Report===============================\n\n')
        #Check VT answer
        for i in value:
            if value['response_code']==0:
                print('Nothing ¯\_(ツ)_/¯')
                break
        else:
            total = pd.DataFrame({'Name':['permalink','positives','scan_date','sha256','total','verbose_msg'],'Value':[value['permalink'], value['positives'], value['scan_date'], value['sha256'], value['total'],value['verbose_msg']]})
            print(total)


def hybrid_analyser_hash(argument):
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



def hybrid_analyser_sandbox(filepath, env):
    headers = {
    'accept': 'application/json',
    'user-agent': 'Falcon Sandbox',
    'api-key': ha_api,
}
    f = open(filepath,'rb')
    files = {'file': (os.path.basename(filepath), f), 'environment_id': (None, env)}
    response = requests.post(ha_sandbox, headers=headers, files=files)
    value = response.json()
    f.close()
    global ha_val
    ha_val = value['job_id']
    global ha_hash
    ha_hash= value['sha256']

    if response.ok:
        print('[DEBUG] File was ulpoaded to Falcon Sandbox')
        print('job_id:',value['job_id'])
        print('environment_id:',value['environment_id'])
        print('sha256:',value['sha256'])
    else:
        print('Operation Failed.')
    time.sleep(10)
    hybrid_analyser_submitted_info(ha_hash)

def hybrid_analyser_submitted_info(ha_hash):
    hash = ha_hash
    headers = {
    'accept': 'application/json',
    'user-agent': 'Falcon Sandbox',
    'api-key': ha_api,
}
    data = {
  'hashes[]': ha_hash,
}
    response = requests.post(ha_summary, headers=headers, data=data)
    res = response.json()
    print('\n\n\t\t\t\t\t\t\t\t===============================Information From Sandbox===============================n\n')
    return(hash)
'''    for key in res:
        for j in key:
           if(key[j]==[]):
              break
           else:
              print(j,key[j])'''



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