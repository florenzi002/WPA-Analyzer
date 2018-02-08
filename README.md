# WPA2-Analyzer

This project is the final project of the Network Security course @ Università degli Studi di Brescia

## Description
Proof of concept of the fact that, in a WPA2-PSK enviroment, knowing the PSK and snooping a succesful handshake, a 3rd party is able to derive the same PTK as a legitimate client and decrypt the whole session between STA and AP.

## Assumption
The program makes a few assumptions:
 - The session is encrypted using WPA2-PSK (AES CCMP & HMAC SHA1)
 -  We know the PSK
 - All the packets have a PRISM header [144 byte]

## Usage
The program can be compiled using CMake
Once compiled run:

    ./wpa_decode captured_traffic_file decrypted_traffic_destination_file SSID WLAN-PWD

where

 - *captured_traffic_file* is a pcap file of snooped traffic
 - *decrypted_traffic_destination_file* is the path of the file which will hold the decrypted traffic
 - *ssid* is the SSID of the WLAN which traffic we want to decrypt
 - *pwd* is the password of the WLAN which SSID is specified as *ssid* parameter

 
## Prerequisites
The machine is running on UNIX and has **OpenSSL** libraries installed  

## Limitation
The program is focused on decrypting unicast traffic in either direction and doesn't care about multicast traffic.

