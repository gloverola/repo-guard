"""A one-line spinner on stderr ("scanning ... reading files 120/800") while repo-guard works.

Only shown when stderr is a terminal, so pipes, CI logs, JSON/SARIF output and the MCP
server stay clean. Turn it off with REPO_GUARD_NO_PROGRESS=1.
"""

import contextlib
import os
import sys
import threading
import time

_current = None


def _enabled(stream):
    if os.environ.get("REPO_GUARD_NO_PROGRESS") or os.environ.get("CI") or os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


class Spinner:
    def __init__(self, label, stream=None):
        self.stream = stream or sys.stderr
        self.label, self.detail = label, ""
        enc = (getattr(self.stream, "encoding", "") or "").lower().replace("-", "")
        self.frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if enc == "utf8" else "|/-\\"
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self.start_time = time.time()

    def _line(self, frame):
        text = "%s %s" % (frame, self.label) + (" · " + self.detail if self.detail else "")
        try:
            width = os.get_terminal_size(self.stream.fileno()).columns - 1
        except (OSError, ValueError, AttributeError):
            width = 0
        return text[:width if width >= 20 else 79]

    def _run(self):
        i = 0
        while not self._stop.wait(0.1):
            with self._lock:
                self.stream.write("\r\033[K\033[36m%s\033[0m" % self._line(self.frames[i % len(self.frames)]))
                self.stream.flush()
            i += 1

    def start(self):
        self._thread.start()
        return self

    def update(self, detail, label=None):
        self.detail = detail
        if label:
            self.label = label

    def clear(self):
        with self._lock:
            self.stream.write("\r\033[K")
            self.stream.flush()

    def stop(self):
        self._stop.set()
        self._thread.join()
        self.clear()


def status(detail, label=None):
    """Update the running spinner, if any. Cheap enough to call in loops."""
    if _current is not None:
        _current.update(detail, label)


@contextlib.contextmanager
def spinning(label, stream=None):
    global _current
    stream = stream or sys.stderr
    if _current is not None or not _enabled(stream):
        yield
        return
    _current = Spinner(label, stream).start()
    try:
        yield
    finally:
        sp, _current = _current, None
        sp.stop()


@contextlib.contextmanager
def paused():
    """Hide the spinner while something else writes to the terminal (git clone, prompts)."""
    global _current
    sp = _current
    if sp is None:
        yield
        return
    sp._stop.set()
    sp._thread.join()
    sp.clear()
    _current = None
    try:
        yield
    finally:
        new = Spinner(sp.label, sp.stream)
        new.detail = sp.detail
        _current = new.start()
