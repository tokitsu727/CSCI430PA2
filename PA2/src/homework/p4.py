import hashlib
import threading
import binascii
myname = bytearray(b"timothyokitsu")

#Ok, so why python? I got some of the way through the java code and was having to convert
#	types multiple times per loop. It looked really messy, so I decided to switch to python
#	which made the code significantly easier to write. I didn't have enough experience
#	multi-threading in python to write it though, so I just didn't, which proved to be a mistake,
#	as I wasn't able to finish the brute force execution in time.

#I really should've used C, which would've been both simple to write and I have a wealth of experience
#	writing multithreading code in C, but I would've had to either copy or write my own SHA-256
#	implementation which is wholly undesirable.


for nonce in range(2 ** 72):
	nonce_bytes = nonce.to_bytes(10, 'big')
	hash = hashlib.sha256(nonce_bytes + myname).digest()
	if hash[0:4] == b'\x00\x00\x00\x00':
		if hash[4] < 16:
			print(f"Nonce: {nonce}\n")
			print(f"Hash: {binascii.hexlify(bytearray(hash))}\n")
			break