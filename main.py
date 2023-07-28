import socket
import argparse
import os
import requests
import logging

from bs4 import BeautifulSoup

parser = argparse.ArgumentParser(description="ssdp discovery utility is created to discover devices in network")
parser.add_argument("-i", "--ip", default=None, help="leave empty to automatically resolve ip address, or enter it manually")
parser.add_argument("-v", "--verbose", action="store_true", default=False, help="turn debug mode on or off")
args = parser.parse_args()

if args.verbose:
    if "logs" not in os.listdir("."):
        os.mkdir("logs")

def get_logger(name):
    file_name = strftime("[%d-%m-%y] %H-%M-%S.log")

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(path.join("logs", file_name))
    formatter = logging.Formatter(fmt="%(message)s")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    return logger

if args.verbose:
    print("be notified debug mode is ON")
    buffer = ""

print("resolving ip address...", end="")
resolve_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
resolve_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

def resolve_ip():
    try:
        resolve_socket.connect(("10.254.254.254", 1))
        resolved_ip = resolve_socket.getsockname()[0]
        print("done")
    except Exception as e:
        print(e)
        resolved_ip = "127.0.0.1"
    finally:
        resolve_socket.close()
        
    return resolved_ip


def extract_from_xml(input_data):
    bs = BeautifulSoup(input_data, "xml")
    print("\r\n- ROUTER DATA -")
    print("router name: " + bs.find("friendlyName").text)
    print("manufacturer: " + bs.find("manufacturer").text)
    print("serial number: " + bs.find("serialNumber").text)
    print("- END -")


def get_xml_file(address):
    xml_data = requests.get(address).content.decode()

    return xml_data

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.settimeout(2)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if not args.ip:
    sock.bind((resolve_ip(), 9876))
else:
    sock.bind((args.ip, 9876))

server = None
location = None

first_header = "M-SEARCH * HTTP/1.1\r\n" \
        "HOST:239.255.255.250:1900\r\n" \
        "ST:ssdp:all\r\n" \
        "MX:2\r\n" \
        'MAN:"ssdp:discover"\r\n' \
        "\r\n"
print("sending to broadcast...", end="")
sock.sendto(first_header.encode("utf-8"), ("239.255.255.250", 1900))
print("done")
while True:
    try:
        data, addr = sock.recvfrom(8192)
        if not args.verbose:
            for line in data.decode().split("\r\n"):
                if line[0:6] == "SERVER" and not server:
                    server = line
                    print(line)
                
                if line[0:8] == "LOCATION" and not location:
                    location = line
                    print(line)

                if line[0:2] == "ST":
                    print(line)
        else:
            print(data.decode())
            for line in data.decode().split("\r\n"):
                if line[0:8] == "LOCATION" and not location:
                    location = line

                if line[0:6] == "SERVER" and not server:
                    server = line

    except (KeyboardInterrupt, socket.timeout):
        xml = get_xml_file(location[10:])
        extract_from_xml(xml)
        break
