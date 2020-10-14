# -*- coding:utf-8 -*-

import re
import os
import time
import shutil
import subprocess

from settings import *
from pathlib import Path
from monitor.file_monitor import Target

#========================================================================================

class CreateObserverDir(Target):

    def __init__(self, watchDir):
        super().__init__(watchDir)

    def on_created(self, event):
        try:
            time.sleep(15)
            
            fp = re.search(r"src_path='(.*)report.*'",str(event))           # created event regex filter
            new_log = str(Path(fp.group(1)))                                # use Path method 

            CMD = 'cd ' + new_log + ' & ' + CURL
            proc = subprocess.Popen(CMD, shell=True)                        # send new_log to Queue
            proc.wait()
            time.sleep(10)
            
            rep_path = os.path.join(new_log, 'report.json')
            os.remove(rep_path)
            
        except Exception as e:
            print(e)



