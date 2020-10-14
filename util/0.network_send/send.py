import os
import subprocess
import time
import shutil

#Edit_json -> report.py
from .report import json_filter


REMOTE_PATH = r'[JSON FOLDER PATH]\report.json'

REMOTE_IP = '[IP]'
REMOTE_USER = '[USERNAME]'
REMOTE_PASSWD = '[PW]'


def _remove(path):
    time.sleep(7)
    shutil.rmtree(path)


def send_report(REPORT_PATH, analysis_path):
    try:
       result = os.path.split(REPORT_PATH)
       _path = os.path.join(result[0], 'report_patch.json')
       json_filter(REPORT_PATH)
       CMD = 'sshpass -p ' + REMOTE_PASSWD + ' scp ' + _path + ' ' + REMOTE_USER +'@' + REMOTE_IP + ':' + REMOTE_PATH
       subprocess.Popen(CMD,shell=True)
       _remove(analysis_path)
    except Exception as e:
       print(e)
