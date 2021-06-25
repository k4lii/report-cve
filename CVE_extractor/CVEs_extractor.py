import sys
import urllib
import json
import time
import datetime
import requests

#set global variables
arg_day_before = 7
arg_path = "/home/OPSTools.json"

try:
    file = open("/home/config.json", 'r', encoding='utf-8')
    config_data = json.load(file)
    if(config_data['opencve_user'] == None or config_data['opencve_password'] == None):
        print("Tool need opencve credentials")
        sys.exit(84)
    if(config_data['days_before'] != None):
        arg_day_before = config_data['days_before']
    if(config_data['path'] != None):
        arg_path = config_data['path']
except:
    print("[ERROR] config.json -> Bad formatting or file not existing")
    sys.exit(84)

#compare 2 dates %Y-%m-%d -> True if first_date is more recent|equal to second_date
def compare_date(first_date):
    if(config_data['date'] == None):
        second_date = (datetime.datetime.now() - datetime.timedelta(days=arg_day_before)).strftime('%Y-%m-%d')
    else:
        second_date = config_data['date']
    formatted_date1 = time.strptime(first_date, "%Y-%m-%d")
    formatted_date2 = time.strptime(second_date, "%Y-%m-%d")
    if (formatted_date1 > formatted_date2):
        return(True)
    elif(formatted_date1 < formatted_date2):
        return(False)
    return(True)

#return log line for differents cvvs versions in cve's datas AND prefer cvvs3(all cves not contain cvvs2/cvvs3)
def Gen_Logs_By_CVVS_Version(data_cve, date, cve, cpe):
    cpe_parse = [str(item) for item in cpe.split(':')]
    log_start =  date + " " + cpe_parse[3] + ':' + cpe_parse[4] + ':' + cpe_parse[5]
    log_end = " " + "https://www.opencve.io/cve/" + cve
    if (data_cve['cvss']['v3'] != None):
        severity = data_cve['raw_nvd_data']['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        log = log_start + " cvss3 " + severity + " "+ str(data_cve['raw_nvd_data']['impact']['baseMetricV3']['cvssV3']['baseScore']) + " " + data_cve['raw_nvd_data']['impact']['baseMetricV3']['cvssV3']['attackVector'] + log_end
        return(log, severity)
    elif (data_cve['cvss']['v2'] != None):
        severity = data_cve['raw_nvd_data']['impact']['baseMetricV2']['severity']
        log = log_start + " cvss2 " + severity + " " + str(data_cve['raw_nvd_data']['impact']['baseMetricV2']['cvssV2']['baseScore']) + " " + data_cve['raw_nvd_data']['impact']['baseMetricV2']['cvssV2']['accessVector'] + log_end
        return(log, severity)
    else:
        return(log_start + " N/A" + " N/A" + " N/A" + " N/A" + log_end, "None")

# repeat requests while the api isn't working/responding
def openCveApi_repeat_requests(cve, cpe):
    try:
        r = requests.get('https://www.opencve.io/api/cve/' + cve, auth=(config_data['opencve_user'], config_data['opencve_password']))
        data_cve = r.json()
        date = data_cve['updated_at'].rpartition('T')[0]
        if(compare_date(date)):
            log, severity = Gen_Logs_By_CVVS_Version(data_cve, date, cve, cpe)
            if(config_data['severity'] == None):
                print(log)
            else:
                for item in config_data['severity']:
                    if(item == severity):
                        print(log)
    except requests.exceptions.HTTPError as errh:
        print(errh)
        time.sleep(1) #1s cooldown between each new request
        openCveApi_repeat_requests(cve, cpe)

#retrive cve infos from opencve and make operation on cve(compare date/severity) and print on stdout
def CVEs_to_Logs(cves, cpe):
    for cve in cves:
        openCveApi_repeat_requests(cve, cpe)

# take tools infos in Opstools.json and convert it to cpes list
def Gen_CPEs(data):
    cpe_test_pattern = "cpe:2.3:" ; x = 0 ; cpes = []
    while(x != len(data['version'])):
        cpes.append(cpe_test_pattern + data['sys_type'] + ":" + data['vendor'] + ":" + data['tool'] + ":" + str(data['version'][x]))
        x+=1
    return(cpes)

# repeat requests while the api isn't working/responding
def NvdApi_repeat_requests(cpe):
    try:
        r = urllib.request.urlopen('https://services.nvd.nist.gov/rest/json/cpes/1.0?addOns=cves&cpeMatchString=' + cpe)
        data_json = json.loads(r.read())
        if(int(data_json['totalResults']) <= 0): #if a cpe dont exist, no cves exist, so check another version
            return
        cves = data_json['result']['cpes'][0]['vulnerabilities']
        CVEs_to_Logs(cves, cpe)
    except urllib.error.HTTPError as errh:
        print(errh)
        time.sleep(1)
        NvdApi_repeat_requests(cpe)

# get cves numbers thanks to cpes name with NVD Api
def Get_CVEs(cpes):
    for cpe in cpes:
        NvdApi_repeat_requests(cpe)

# open Opstools.json and main loop
def main():
    i = 0
    try:
        file = open(arg_path, 'r', encoding='utf-8')
        data = json.load(file)
    except:
        print("[ERROR] Bad json formatting or file not existing")
        sys.exit(84)
    while(i != len(data)):
        cpes = Gen_CPEs(data[i])
        Get_CVEs(cpes)
        i += 1

#call main & handle CTRL + C (useful if script is used without docker)
try:
    main()
    sys.exit(0)
except KeyboardInterrupt:
    print("FORCED EXIT")
    sys.exit(84)