#!/usr/bin/python3
#
import sys
import argparse
import struct

magic_hdr = 0xe9e63f1c # randomly generated header that marks the start of the BOF header

# Bof header:
# 4 bytes <magic_hdr> 0xe9e63f1c
# 4 byte <boff_len> (little endian encoded size of the BOF file in bytes)
# <boff_len> bytes BOF (raw BOF data)

def main():
    parser = argparse.ArgumentParser(description='BOF2Shellcode')
    parser.add_argument('-i', dest='bof_file', help='BOF Input File', type=str, required=True)
    parser.add_argument('-o', dest='output_file', help='Output file to write to', required=True)
    parser.add_argument('-l', dest='loader', help='Shellcode loader filename, default bofloader.bin', default='bofloader.bin')
    args = parser.parse_args()

    payload = open(args.loader, 'rb').read()
    bof_payload = open(args.bof_file, 'rb').read()
    payload += struct.pack("<L", magic_hdr)
    payload += struct.pack("<L", len(bof_payload))
    payload += bof_payload

    print(f"Writing {args.output_file}")
    open(args.output_file, 'wb').write(payload)

if __name__ == '__main__':
    main()
