#!/usr/bin/env python3.6


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


VT_API_KEY = ''
PROXY = '' # Proxy format : http://user:mdp@addr:port
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"


def proxy():
    return {"https": PROXY, "http": PROXY}


def main():
    parser = argparse.ArgumentParser(description='Check files hashes on VirusTotal')
    parser.add_argument('-f', '--filepath')
    parser.add_argument('-d', '--directory')
    parser.add_argument('-l', '--hash_list')
    parser.add_argument('-i', '--ipaddr_file')
    args = parser.parse_args() 

    logging.basicConfig(filename='info.log', level=logging.INFO)
    result_file = open('result.txt', 'w')

    if args.filepath:
        vt_check(args.filepath, result_file)

    elif args.directory:
        directory_path = os.fsencode(args.directory)
        for f in tqdm(os.listdir(directory_path)):
            filename = os.fsencode(f)
            aFilename = filename.decode("utf-8")
            full_path = str(args.directory) + "/" + str(aFilename)
            vt_check(full_path, result_file)

    elif args.hash_list:
        list_path = os.fsencode(args.hash_list)
        with open(list_path) as f:
            lines = [line.rstrip() for line in f]
            for lHash in tqdm(lines):
                if vt_check_hash(lHash):
                    logging.info("File " + str(lHash) + " is flagged as malicious on VirusTotal")
                    result_file.write(str(lHash) + "\n")
                else:
                    logging.info("File " + str(lHash) + " is safe for VirusTotal")

    elif args.ipaddr_file:
        #vt_check_ip(args.ipaddr_file, result_file)
        vt_check_ip_whois_test(args.ipaddr_file, result_file)

    else:
        print("Invalid argument")

    result_file.close()


def vt_check_ip_whois_test(ip_file, rfile):
    '''
    function to use to test the whois queries
    '''
    whois_file = open("whois_results.txt", "w")
    with open(ip_file) as f:
        for line in tqdm(f.readlines()):
            ip_addr = line.rstrip()
            ret = extract_from_whois(ip_addr) 
            print(ret)
    close(whois_file)


def vt_check_ip(ip_file, rfile):
    whois_file = open("whois_results.csv", "w")
    with open(ip_file) as f:
        headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
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

                if "whois" in result["data"]["attributes"]:
                    whois_str = result["data"]["attributes"]["whois"]
                    extracted = False
                    if "No match" in whois_str:
                        logging.info("No whois information for " + str(ipaddr))
                    else:
                        extract = str(ipaddr) + ","
                        if "Country:" in whois_str:
                            extract = extract_from_whois(extract, whois_str, "country:")
                            extracted = True
                        elif "OriginAS:" in whois_str:
                            extract = extract_from_whois(extract, whois_str, "OriginAS:")
                            extracted = True
                        elif "Organization:" in whois_str:
                            extract = extract_from_whois(extract, whois_str, "Organization:")
                            extracted = True
                        else:
                            logging.info("The whois information for " + str(ipaddr) + " doesn't have Country, OriginAS, nor Organization information")
                    if extracted:
                        whois_file.write(extract.rstrip(",") + "\n")
    whois_file.close()


def extract_from_whois(sIP):
    obj = IPWhois(sIP)
    result = obj.lookup_rdap()
    return result
                

def vt_check_hash(filehash):
    '''check on VT if 'filehash' is the hash of a malicious file'''
    client = vt.Client(VT_API_KEY, trust_env=True)
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


def vt_check(filepath, rfile):
    with open(filepath, "rb") as f:
        data = f.read()
        md5_string = hashlib.md5(data).hexdigest()
        if vt_check_hash(md5_string):
            logging.info("File " + str(filepath) + " is flagged as malicious on VirusTotal")
            rfile.write(str(filepath) + "\n")
        else:
            logging.info("File " + str(filepath) + " is safe for VirusTotal")

if __name__ == '__main__':
    main()
