import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class MyHandler(FileSystemEventHandler):
    """
    handle file changes
    """
    def on_modified(self, event):
        print('the client took the bait! the new information is:\n')
        with open('/var/www/html/client_info.txt','r') as f:
            print(f.read()+"\n")


def start_listen():
    """
    listening to changes in the file:  /var/www/html/client_info.txt
    """
    event_handler = MyHandler()
    observer = Observer()
    observer.schedule(event_handler, path='/var/www/html/client_info.txt', recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
