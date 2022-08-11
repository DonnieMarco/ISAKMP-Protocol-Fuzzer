#! /usr/bin/python3

"""
IKEv2 ISAKMP exchange fuzzing script written by MarcHill@BramleySecurityTesting.co.uk
"""

from random import randint
from scapy.all import *
from time import sleep

import argparse, sys, socket, os, subprocess, re

# Define the command line arguments to import the pcap.
parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", type=str, required=True, help="The .pcap file to import")
args = parser.parse_args()
print (args.file)
pcap = args.file
p = rdpcap(pcap)

# Modify the following integer to create the isakmpInit variable that contains the IKEv2 exchange frame. Remember Wireshark indexing starts at 1, but Python indexes start at 0. So whatever the index number is in Wireshark, the index for the isakmpInit variable will be minus 1.
isakmpInit = p[220]

# The mutate function takes the data extracted from the packet (originalData) and passes it into the mutate functions as the payload argument. The mutate() function then creates a bash one-liner that uses echo to pipe the payload into radamsa. The command is executed and the output is stored as the variable mutatedData.
def mutate(payload):
	# Data extracted using scapy is byte encoded, it is therefore necessary to strip the first 'b' from the payload before passing through radamsa.
	payload = str(payload)
	payload = payload[1:]

	try:
		radamsa = ("echo " + payload + " | " + "radamsa -n 1")
		print("\nThe following bash one-liner will be executed to generate the mutatedData")
		print (radamsa)
		#print ("\n____________________________________")
		mutatedData = subprocess.check_output(radamsa, shell=True)
		print("\nThis is the mutated data:")
		print(mutatedData)
		print ("\n____________________________________")
	except:
		print ("Could not execute radamsa")
		sys.exit(1)

	return mutatedData

# Print the packet capture to the screen, and pause before beginning to fuzz
print ("\n____________________________________")
print ("\nThis is the original packet capture: \n")
originalPkt = isakmpInit.show()
print (originalPkt)
print ("____________________________________")
print ("\nMutating data and fuzzing the ISAKMP.resp_cookie\n")
sleep(2)

# Here the data to be mutated is extracted and assigned to a variable
originalData = isakmpInit['ISAKMP'].resp_cookie
# Print the extracted data to the terminal
displayData = originalData[1:]
print(displayData)

# Delete the datagram checksums / len
def delChksums():
	del isakmpInit['IP'].len
	del isakmpInit['IP'].chksum
	del isakmpInit['UDP'].len
	del isakmpInit['UDP'].chksum
	del isakmpInit['UDP'].chksum

while(True):
	# Send the Packets till they crash!!!
	isakmpInit['IP'].id = randint(1000, 99999)
	newData = mutate(originalData)
	isakmpInit['ISAKMP'].resp_cookie = newData
	"""
	The following used only for debug purposes
	print ("\n____________________________________")
	print ("\nThis is the new packet with mutatedData\n")
	newPkt = isakmpInit.show()
	print (newPkt)
	"""
	# Delete and recalculate the IP checksums/len, then rebuild the ethernet frame before sending.
	try:
		delChksums()
		Ether(isakmpInit.build())
		print ("____________________________________")
		print ("\nSending the following fuzzy packet\n")
		print (isakmpInit.show)
		sendp(isakmpInit)
		print ("\n____________________________________")
		#i += 1
		sleep(0.25)
	except:
		print ("\nMutated packet failed to send")
		print ("\n____________________________________")
sys.exit(1)
