#-*- coding: utf-8 -*-
import json
import os
import re
import subprocess

#ipaddress -> geopoint // return lat, lot
def geo_point(ip_address):
    cmd = 'curl http://ip-api.com/json/'+ip_address+'?fields=lat,lon'
    result = subprocess.check_output(cmd, shell=True)
    geo_data = result.decode('utf-8')
    
    lat = re.search('.*"lat":(.*),',geo_data)
    lon = re.search('.*"lon":(.*)}',geo_data)
    return float(lat.group(1)), float(lon.group(1))


def json_filter(path):
    result = os.path.split(path)
    report_path = os.path.join(result[0])

    #open json file
    with open(path, 'r') as j_obj:
        j_data = json.load(j_obj)
        
        #del j_data['CAPE']['cape_yara']
        #j_data['behavior']['summary'] = '[]'
        j_data['behavior']['enhanced'] = '[]'
        del j_data['virustotal']


        #dropped
        for row in range(len(j_data['dropped'])):
            pp = re.search(".*('data':).*",str(j_data['dropped'][row]))
            if None != pp:
               del j_data['dropped'][row]['data']


        #procdump
        for row in range(len(j_data['procdump'])):
            pp = re.search(".*('cape_yara':).*",str(j_data['procdump'][row]))
            if None != pp:
               if '[]' != str(j_data['procdump'][row]['cape_yara']):
                   for row2 in range(len(j_data['procdump'][row]['cape_yara'])):
                       pp2 = re.search(".*('strings':).*",str(j_data['procdump'][row]['cape_yara'][row2]))
                       pp3 = re.search(".*('addresses':).*",str(j_data['procdump'][row]['cape_yara'][row2]))
                       if None != pp2:
                          del j_data['procdump'][row]['cape_yara'][row2]['strings']
                       if None != pp3:
                          del j_data['procdump'][row]['cape_yara'][row2]['addresses']


        #CAPE/cape_yara
        for row in range(len(j_data['CAPE'])):
            pp = re.search(".*('cape_yara':).*",str(j_data['CAPE'][row]))
            if None != pp:
                if '[]' != str(j_data['CAPE'][row]['cape_yara']):
                   for row2 in range(len(j_data['CAPE'][row]['cape_yara'])):
                       pp2 = re.search(".*('addresses':).*",str(j_data['CAPE'][row]['cape_yara'][row2]))
                       if None != pp2:
                          del j_data['CAPE'][row]['cape_yara'][row2]['addresses']


        #behavior/processes/calls
        for row in range(len(j_data['behavior']['processes'])):
            for row2 in range(len(j_data['behavior']['processes'][row]['calls'])):
                del j_data['behavior']['processes'][row]['calls'][row2]['thread_id']
                del j_data['behavior']['processes'][row]['calls'][row2]['timestamp']
                del j_data['behavior']['processes'][row]['calls'][row2]['caller']
                del j_data['behavior']['processes'][row]['calls'][row2]['parentcaller']
                del j_data['behavior']['processes'][row]['calls'][row2]['return']
                del j_data['behavior']['processes'][row]['calls'][row2]['repeated']
                del j_data['behavior']['processes'][row]['calls'][row2]['arguments']
                del j_data['behavior']['processes'][row]['calls'][row2]['id']
                del j_data['behavior']['processes'][row]['calls'][row2]['status']

             
        #debug, strings
        j_data['debug'] = '[]'
        #j_data['strings'] = '[]'


        #Add network/hosts/location
        for row in range(len(j_data['network']['hosts'])):
            ip = j_data['network']['hosts'][row]['ip']
            lat, lon = geo_point(ip)
            j_data['network']['hosts'][row]['location'] = {}
            j_data['network']['hosts'][row]['location']['lat'] = lat
            j_data['network']['hosts'][row]['location']['lon'] = lon
        

    #save json file
    with open(os.path.join(report_path,'report_patch.json'), 'w') as f:
       json.dump(j_data, f, indent=4, separators=(',',': '))

     
    
