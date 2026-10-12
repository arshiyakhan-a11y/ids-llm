import os


def read_new_lines(path, offset, max_lines=5000):
    """Return (complete_lines, new_offset). Partial last line is left for next call.
    If the file shrank (rotated/truncated) reading restarts from 0."""
    if not os.path.exists(path):
        return [], offset
    if os.path.getsize(path) < offset:
        offset = 0
    lines = []
    with open(path, "rb") as f:
        f.seek(offset)
        while len(lines) < max_lines:
            pos = f.tell()
            line = f.readline()
            if not line:
                break
            if not line.endswith(b"\n"):
                f.seek(pos)
                break
            lines.append(line.decode("utf-8", "replace").rstrip("\r\n"))
        new_off = f.tell()
    return lines, new_off
