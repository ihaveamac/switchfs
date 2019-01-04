import logging
from argparse import ArgumentParser, SUPPRESS
from functools import wraps
from sys import exit, platform
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Generator, Tuple, Union

windows = platform in {'win32', 'cygwin'}
macos = platform == 'darwin'

# TODO: switch to use_ns in all scripts
# noinspection PyBroadException
try:
    from fuse import FUSE, FuseOSError, Operations, fuse_get_context
except Exception as e:
    exit(f'Failed to import the fuse module:\n'
         f'{type(e).__name__}: {e}')


# custom LoggingMixIn modified from the original fusepy, to suppress certain entries.
class LoggingMixIn:
    log = logging.getLogger('fuse.log-mixin')

    def __call__(self, op, path, *args):
        if op != 'access':
            self.log.debug('-> %s %s %s', op, path, repr(args))
        ret = '[Unhandled Exception]'
        try:
            ret = getattr(self, op)(path, *args)
            return ret
        except OSError as e:
            ret = str(e)
            raise
        finally:
            if op != 'access':
                self.log.debug('<- %s %s', op, repr(ret))


default_argp = ArgumentParser(add_help=False)
default_argp.add_argument('-f', '--fg', help='run in foreground', action='store_true')
default_argp.add_argument('-d', help='debug output (fuse/winfsp log)', action='store_true')
default_argp.add_argument('--do', help=SUPPRESS, default=None)  # debugging using python logging
default_argp.add_argument('-o', metavar='OPTIONS', help='mount options')

readonly_argp = ArgumentParser(add_help=False)
readonly_argp.add_argument('-r', '--ro', help='mount read-only', action='store_true')


def main_args(name: str, help: str) -> ArgumentParser:
    parser = ArgumentParser(add_help=False)
    parser.add_argument(name, help=help)
    parser.add_argument('mount_point', help='mount point')
    return parser


# aren't type hints great?
def parse_fuse_opts(opts) -> 'Generator[Tuple[str, Union[str, bool]], None, None]':
    if not opts:
        return
    for arg in opts.split(','):
        if arg:  # leaves out empty ones
            separated = arg.split('=', maxsplit=1)
            yield separated[0], True if len(separated) == 1 else separated[1]


def ensure_lower_path(method):
    @wraps(method)
    def wrapper(self, path, *args, **kwargs):
        return method(self, path.lower(), *args, **kwargs)
    return wrapper
