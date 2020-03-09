import sys
import logging
import time


class PrettyFormatter(logging.Formatter):

    def __init__(self):
        fmt = '%(asctime)s %(levelname)s %(pathname)s:%(lineno)s (in %(funcName)s): %(message)s'  # noqa E501
        datefmt = '%Y-%m-%d %H:%M:%S'
        super().__init__(fmt, datefmt)
        self.whitespace = ' ' * (len(time.strftime(datefmt)))

    def formatMessage(self, msg):
        original = super().formatMessage(msg)
        return original.replace('\n', ' ')

    def formatException(self, exc):
        original = super().formatException(exc)
        lines = []
        for line in original.split('\n'):
            lines.append(f'{self.whitespace} | {line}')
        return '\n'.join(lines)


logger = logging.getLogger('openshift-csr-approver')
logger.setLevel(logging.INFO)

stdout = logging.StreamHandler(sys.stdout)
stdout.setFormatter(PrettyFormatter())
logger.addHandler(stdout)
