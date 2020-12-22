import sys

def wrap_print(arg, *args):
    line_length = 68
    string = arg + " " + " ".join(args)
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            print(hunk)

def print_value(name, value):
    wrap_print(name + ' = ' + value)

for line in sys.stdin:
    data = line.strip().split(": ")
    print_value(data[0], data[1])