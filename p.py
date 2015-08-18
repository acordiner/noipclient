from time import sleep
from daemon.runner import DaemonRunner


class App(object):

    def __init__(self):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/tmp/stdout.txt'
        self.stderr_path = '/tmp/stderr.txt'
        # self.pidfile_path =  '/tmp/foo.pid'
        # self.pidfile_timeout = 5

    def run(self):
        while True:
            print("Hello!")
            sleep(10)


def main(argv):
    app = App()
    runner = DaemonRunner(app)
    print("parsing")
    #runner.parse_args(argv)
    #runner.do_action()

if __name__ == '__main__':
    main(['p.py', 'start'])