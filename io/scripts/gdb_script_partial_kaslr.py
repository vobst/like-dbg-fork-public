import gdb
import sys

sys.path.insert(0, "/root/scripts")

from lkd.boot import boot_into_paritalASLR


def main():
    boot_into_paritalASLR()


main()
