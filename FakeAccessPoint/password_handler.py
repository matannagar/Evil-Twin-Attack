import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class MyHandler(FileSystemEventHandler):
    """
    This class is used for listening to file change event...
    """

    def on_modified(self, event):
        print(
            'Someone has just been hacked,New password came , please look the /var/www/html/client_info.txt file'
            ' for more information')


def start_listen():
    """
    start listening to  file change events on >> /var/www/html/passwords.txt << (hard coded)
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
