from argparse import ArgumentParser, Namespace
import os.path


def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error(f"The file {arg} does not exist")
    else:
        return arg


def main():
    parser = ArgumentParser()

    parser.add_argument("filename", help="Scans a given file", type=lambda x: is_valid_file(parser, x))
    parser.add_argument("-c", "--csv", help="Export results to a csv file", action="store_true")
    parser.add_argument("-p", "--pdf", help="Export results to a pdf file", action="store_true")

    args: Namespace = parser.parse_args()

    with open(args.filename, "r") as f:
        print(f.readline())

    if args.csv:
        pass
    if args.pdf:
        pass






