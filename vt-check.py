#!/usr/bin/env python3


__author__ = 'Nicolas Ooghe'


import vt
import json
import csv
import requests
import os
import argparse
import hashlib
import time
import logging
from tqdm import tqdm
from ipwhois import IPWhois


CONFIG_FILE = "config.json"
VT_API_KEY = ""
PROXY = "" # Proxy format : http://user:mdp@addr:port
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"


def proxy():
    proxy = get_proxy_cfg()
    return {"https": proxy, "http": proxy}


def get_api_key():
    api_key = ''
    with open(CONFIG_FILE, 'r') as cfg:
        config = json.load(cfg)
        api_key = config['api_key']
    return api_key


def get_proxy_config():
    proxy_cfg = ''
    with open(CONFIG_FILE, 'r') as cfg:
        config = json.load(cfg)
        proxy_cfg = config['proxy']
    return proxy_cfg


def main():
    parser = argparse.ArgumentParser(description='Check files hashes on VirusTotal')
    parser.add_argument('-f', '--filepath')
    parser.add_argument('-d', '--directory')
    parser.add_argument('-l', '--hash_list')
    parser.add_argument('-i', '--ipaddr_file')
    args = parser.parse_args() 

    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        filename='info.log',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO)
    vt_api_key = get_api_key()
    result_file = open('result.txt', 'w')

    if args.filepath:
        vt_check(args.filepath, result_file, vt_api_key)

    elif args.directory:
        directory_path = os.fsencode(args.directory)
        for f in tqdm(os.listdir(directory_path)):
            filename = os.fsencode(f)
            aFilename = filename.decode("utf-8")
            full_path = str(args.directory) + "/" + str(aFilename)
            vt_check(full_path, result_file, vt_api_key)

    elif args.hash_list:
        list_path = os.fsencode(args.hash_list)
        with open(list_path) as f:
            lines = [line.rstrip() for line in f]
            for lHash in tqdm(lines):
                if vt_check_hash(lHash, vt_api_key):
                    logging.info("File " + str(lHash) + " is flagged as malicious on VirusTotal")
                    result_file.write(str(lHash) + "\n")
                else:
                    logging.info("File " + str(lHash) + " is safe for VirusTotal")

    elif args.ipaddr_file:
        print("Checking IP addresses reputation...")
        vt_check_ip(args.ipaddr_file, result_file, vt_api_key)
        print("Getting WHOIS information...")
        get_ip_whois(args.ipaddr_file)

    else:
        parser.print_help()

    result_file.close()


def extract_from_whois(sIP):
    '''
    This function queries the whois DB for an IP address
    arg: 'sIP' is an IPv4 address
    '''
    obj = IPWhois(sIP)
    ret = obj.lookup_rdap()
    return ret


def get_ip_whois(ip_file):
    '''
    This function extracts whois information for each IP address in the IP file
    arg: 'ip_file' is a path to a file containing one IP address per line
    '''
    whois_fields_needed = ["asn_country_code", "asn_description", "asn", "query"]
    whois_file = open("whois_results.csv", "w")
    whois_file.write("IP,ASN,COUNTRY_CODE,ORGANIZATION\n")
    with open(ip_file) as f:
        for line in tqdm(f.readlines()):
            ip_addr = line.rstrip()
            dwhois = extract_from_whois(ip_addr) 
            sOrg = dwhois["asn_description"].split(",")[0]
            whois_file.write(dwhois["query"] + "," + dwhois["asn"] + "," + dwhois["asn_country_code"] + "," + sOrg + "\n")
    whois_file.close()


def vt_check_ip(ip_file, rfile, vt_api_key):
    '''
    Checks the reputation of each IP address referenced in 'ip_file' on VirusTotal
    arg: 'ip_file' is a path to a file containing one IP address per line
    '''
    whois_file = open("whois_results.csv", "w")
    with open(ip_file) as f:
        headers = {"accept": "application/json", "x-apikey": vt_api_key}
        for line in tqdm(f.readlines()):
            ipaddr = line.rstrip()
            url = VT_URL + str(ipaddr)
            response = requests.get(url, headers=headers)
            result = json.loads(response.text)
            if "error" in result:
                logging.info("No result for : " + str(ipaddr))
            else:
                malicious_count = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
                if malicious_count > 0:
                    logging.info("IP " + str(ipaddr) + " is flagged as malicious on VirusTotal")
                    rfile.write(str(ipaddr) + "\n")
                else:
                    logging.info("IP address " + str(ipaddr) + " is safe for VirusTotal")


def vt_check_hash(filehash, vt_api_key):
    '''
    Checks on VT if 'filehash' is the hash of a malicious file
    arg: 'filehash' is a MD5, SHA1, or SHA256 hash
    '''
    client = vt.Client(vt_api_key, trust_env=True)
    res = False
    try:
        vtfile = client.get_object("/files/" + str(filehash))
        logging.info("File " + str(filehash) + " found on VirusTotal:")
        logging.info(vtfile.last_analysis_stats)
        if vtfile.last_analysis_stats["malicious"] > 0:
            res = True
        else:
            res = False
    except vt.error.APIError as e:
        logging.error(e.message)
    client.close()
    return res


def vt_check(filepath, rfile, vt_api_key):
    '''
    Checks the reputation of the file at 'filepath' on VirusTotal
    arg: filepath is the path to the file to be checked
    '''
    with open(filepath, "rb") as f:
        data = f.read()
        md5_string = hashlib.md5(data).hexdigest()
        if vt_check_hash(md5_string, vt_api_key):
            logging.info("File " + str(filepath) + " is flagged as malicious on VirusTotal")
            rfile.write(str(filepath) + "\n")
        else:
            logging.info("File " + str(filepath) + " is safe for VirusTotal")

if __name__ == '__main__':
    main()
