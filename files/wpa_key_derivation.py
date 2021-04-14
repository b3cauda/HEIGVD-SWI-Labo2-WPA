#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__ = "Abraham Rubinstein et Yann Lederrey"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

# Fix for scapy in needed: FileNotFoundError: [Errno 2] No such file or directory: b'liblibc.a' "
# https://stackoverflow.com/questions/65410481/filenotfounderror-errno-2-no-such-file-or-directory-bliblibc-a
from scapy.all import *
from scapy.contrib.wpa_eapol import WPA_key
from scapy.layers.dot11 import Dot11AssoReq
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
import hmac, hashlib


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


def getAssoReqInfo(wpa):
    # Find an association request packet to extract ssid, apmac and clientmac
    pktAssoReq = ''
    for pkt in wpa:
        # Use Scapy Dot11AssoReq to find the packet containing the association request layer
        # https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html#scapy.layers.dot11.Dot11AssoReq
        if pkt.haslayer(Dot11AssoReq):
            pktAssoReq = pkt
            break
    ssid = pktAssoReq.info.decode()  # expect: SWI
    APmac = a2b_hex(pktAssoReq.addr2.replace(':', ''))  # expect: cebcc8fdcab7
    Clientmac = a2b_hex(pktAssoReq.addr1.replace(':', ''))  # expect: 0013efd015bd
    return ssid, APmac, Clientmac


def getWPAKeyInfo(wpa):
    # Find the 4 packets of the handshake to extract anonce, snonce, mic and data
    pktHandshake = []
    for pkt in wpa:
        # Use Scapy WPA_key to find the packets of the handshake
        # https://scapy.readthedocs.io/en/latest/api/scapy.contrib.wpa_eapol.html#scapy.contrib.wpa_eapol.WPA_key
        if pkt.haslayer(WPA_key):
            pktHandshake.append(pkt.getlayer(WPA_key))
        if len(pktHandshake) == 4:
            break
    # Get Authenticator and Supplicant Nonces
    ANonce = pktHandshake[0].nonce  # expect: 90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91
    SNonce = pktHandshake[1].nonce  # expect: 7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577
    # This is the MIC contained in the 4th frame of the 4-way handshake
    # When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
    mic_to_test = pktHandshake[3].wpa_key_mic  # expect: 36eef66540fa801ceee2fea9b7929b40
    # Set MIC to 0 before reading data
    pktHandshake[3].getlayer(WPA_key).wpa_key_mic = 0
    # Get data from the 4th packet
    data = bytes(pktHandshake[3].underlayer)
    return ANonce, SNonce, mic_to_test, data

def main():
    # Read capture file -- it contains beacon, authentication, association, handshake and data
    wpa = rdpcap("wpa_handshake.cap")

    # Important parameters for key derivation - most of them can be obtained from the pcap file
    passPhrase = "actuelle"
    A = "Pairwise key expansion"  # this string is used in the pseudo-random function

    # Get info from association request and WPA key packets
    ssid, APmac, Clientmac = getAssoReqInfo(wpa)
    ANonce, SNonce, mic_to_test, data = getWPAKeyInfo(wpa)

    B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)  # used in pseudo-random function

    print("\n\nValues used to derivate keys")
    print("============================")
    print("Passphrase: ", passPhrase, "\n")
    print("SSID: ", ssid, "\n")
    print("AP Mac: ", b2a_hex(APmac), "\n")
    print("CLient Mac: ", b2a_hex(Clientmac), "\n")
    print("AP Nonce: ", b2a_hex(ANonce), "\n")
    print("Client Nonce: ", b2a_hex(SNonce), "\n")

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(passPhrase)
    ssid = str.encode(ssid)
    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

    # expand pmk to obtain PTK
    ptk = customPRF512(pmk, str.encode(A), B)

    # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16], data, hashlib.sha1)

    print("\nResults of the key expansion")
    print("=============================")
    print("PMK:\t\t", pmk.hex(), "\n")  # expect: f26d2c5bea9d3acbcc735d2a7426c328804383cb4d19da5e90b37842ce71f575
    print("PTK:\t\t", ptk.hex(), "\n")  # expect: 908246499e0dd506a50be26f8bf8c3b912093b5ebc1f1768e1887db6e123015855b0b680ce2459ef02beefbbef427f863af01038e535b2233147ce6e9f742c5e
    print("KCK:\t\t", ptk[0:16].hex(), "\n")
    print("KEK:\t\t", ptk[16:32].hex(), "\n")
    print("TK:\t\t", ptk[32:48].hex(), "\n")
    print("MICK:\t\t", ptk[48:64].hex(), "\n")
    print("MIC:\t\t", mic.hexdigest(), "\n")  # expect: 36eef66540fa801ceee2fea9b7929b40fdb0abaa

if __name__ == '__main__':
    main()