"""Watch a growing log file and hand back only the lines added since the last look.

Think of a bookmark in a book: the tailer remembers how many bytes of the file it has
already read (``offset``). Each call to ``poll()`` reads from the bookmark to the end of
the file, returns the new *complete* lines, and moves the bookmark forward.

It deliberately uses plain polling (look every second or so) instead of OS file-change
notifications. That is a little less elegant, but it behaves the same on Windows, Linux
and macOS and needs no extra libraries.

Quick manual test (prints parsed events as lines are appended to the file):

    python -m siem.tail auth live.log
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class NewLine:
    text: str    # the line, without its trailing newline
    offset: int  # byte position in the file where this line starts


class FileTailer:
    def __init__(self, path: str, from_start: bool = False):
        """``from_start=False`` (default) ignores what is already in the file and only
        reports lines written from now on - what you want when watching a live log.
        ``from_start=True`` also reports the existing content first."""
        self.path = os.fspath(path)
        self.offset = 0
        self._inode = None
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return  # file does not exist yet: when it appears, read it from the top
        self._inode = st.st_ino or None
        if not from_start:
            self.offset = st.st_size

    def poll(self) -> list[NewLine]:
        """Return the complete lines added since the previous call (possibly none)."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            self._inode = None  # file vanished (e.g. mid-rotation): wait for it to return
            return []

        inode = st.st_ino or None
        replaced = bool(self._inode and inode and inode != self._inode)
        if st.st_size < self.offset or replaced:
            self.offset = 0  # file was emptied or swapped for a new one: start over
        self._inode = inode

        if st.st_size == self.offset:
            return []

        with open(self.path, "rb") as fh:  # binary, so offsets are exact byte positions
            fh.seek(self.offset)
            data = fh.read(st.st_size - self.offset)

        last_newline = data.rfind(b"\n")
        if last_newline == -1:
            return []  # only a half-written line so far: leave the bookmark, try again later

        lines, pos = [], self.offset
        for raw in data[: last_newline + 1].split(b"\n")[:-1]:
            text = raw.decode("utf-8", errors="replace").rstrip("\r")
            if text.strip():
                lines.append(NewLine(text, pos))
            pos += len(raw) + 1
        self.offset += last_newline + 1  # move the bookmark past the last complete line
        return lines


def _demo() -> None:
    """Print parsed events as they appear. Stop with Ctrl+C."""
    import argparse
    import time

    from .parsers import PARSERS

    p = argparse.ArgumentParser(prog="python -m siem.tail", description="Watch a log file and print new events.")
    p.add_argument("source", choices=sorted(PARSERS))
    p.add_argument("file")
    p.add_argument("--from-start", action="store_true", help="also process lines already in the file")
    p.add_argument("--year", type=int, help="year for syslog timestamps (auth logs only)")
    args = p.parse_args()

    parser = PARSERS[args.source]
    tailer = FileTailer(args.file, from_start=args.from_start)
    print(f"Watching {args.file} as '{args.source}' logs. Press Ctrl+C to stop.")
    try:
        while True:
            for nl in tailer.poll():
                ev = parser(nl.text, year=args.year) if args.source == "auth" else parser(nl.text)
                if ev is None:
                    print(f"  (not understood) {nl.text[:100]}")
                else:
                    print(f"  {ev.timestamp:%H:%M:%S}  {ev.event_type:<17} ip={ev.src_ip or '-':<15} user={ev.username or '-'}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    _demo()
