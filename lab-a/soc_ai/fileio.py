"""Atomic writes and closed-file snapshots for small dashboard/model artifacts."""
from contextlib import contextmanager
import os
import io
from pathlib import Path
import tempfile
import time


def _temporary_lock(exc):
    # Real permission failures remain errors after the bounded retry window.
    return isinstance(exc, PermissionError) or getattr(exc, 'winerror', None) in (5, 32, 33)


def replace_with_retry(source, destination, timeout=5.0):
    deadline = time.monotonic() + timeout
    delay = .02
    while True:
        try:
            os.replace(source, destination)
            return
        except OSError as exc:
            remaining = deadline - time.monotonic()
            if not _temporary_lock(exc) or remaining <= 0:
                raise
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, .2)


@contextmanager
def atomic_writer(path):
    """Yield a unique binary temp stream; replace only after flush and close."""
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        replace_with_retry(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            # Never mask the original write/replace error during cleanup.
            pass


def read_bytes(path, timeout=5.0):
    """Read a snapshot and release the disk handle before returning bytes.

    Used only for small JSON, charts and checkpoint artifacts, not PCAPs or
    streaming datasets. Retrying does not suppress persistent permission errors.
    """
    deadline = time.monotonic() + timeout
    delay = .02
    while True:
        try:
            with Path(path).open('rb') as stream:
                data = stream.read()
            return data
        except OSError as exc:
            remaining = deadline - time.monotonic()
            if not _temporary_lock(exc) or remaining <= 0:
                raise
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, .2)


def open_shared_read(path):
    """Compatibility API: an in-memory stream, with no open disk handle.

    The old FILE_SHARE_DELETE reader still prevented replacement on the user's
    Windows system. Holding this stream now only holds a snapshot in RAM.
    """
    return io.BytesIO(read_bytes(path))
