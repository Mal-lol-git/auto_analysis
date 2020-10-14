# -*- coding:utf-8 -*-

import time
import queue

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

#========================================================================================

q = queue.Queue()


class Target(FileSystemEventHandler):
    def __init__(self, watchDir):
        self.observer = None
        self.watchDir = watchDir

    def run(self):
        self.observer = Observer()
        self.observer.schedule(self, self.watchDir,
                               recursive=True)
        self.observer.start()

        try:
            while True:
                time.sleep(1)
                
                if not self.status():
                    q.put(self.status())
                    break

                
        except KeyboardInterrupt:
            self.observer.stop()

        self.stop()
        self.observer.join()

    def stop(self):
        self.observer.stop()

    def status(self):
        return self.observer.is_alive()    

    def on_moved(self, event):
        pass

    def on_created(self, event):
        pass

    def on_deleted(self, event):
        pass

    def on_modified(self, event):
        pass
