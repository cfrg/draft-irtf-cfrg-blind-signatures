import sys
import json


def wrap_print(arg, *args):
    line_length = 68
    string = arg + " " + " ".join(args)
    for hunk in (
        string[0 + i : line_length + i] for i in range(0, len(string), line_length)
    ):
        if hunk and len(hunk.strip()) > 0:
            print(hunk)


def print_value(name, value):
    wrap_print(name + " = " + value)


if len(sys.argv) > 1 and sys.argv[1] == "-json":
    vector = {}
    for line in sys.stdin:
        data = line.strip().split(": ")
        if len(data) == 2:
            vector[data[0]] = data[1]
    print(json.dumps([vector]))
else:
    for line in sys.stdin:
        data = line.strip().split(": ")
        if len(data) == 2:
            print_value(data[0], data[1])
