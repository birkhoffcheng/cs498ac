#!/usr/bin/env python

def isalpha(result):
	return result>0x60 and result<0x7b

def bytexor(a, b):
	return bytes([x ^ y for (x,y) in zip (a,b)])

ciphertext_hex = open("ciphertext.txt").readlines()
encrypted_words = [line.split() for line in ciphertext_hex]
ciphertext = [bytes.fromhex(word) for line in encrypted_words for word in line]
key = bytearray()

max_length = 0
for i in ciphertext:
	if len(i) > max_length:
		max_length = len(i)

for i in range(max_length):
	for b in range(0x100):
		false_byte = False
		for w in ciphertext:
			if len(w) <= i or isalpha(b ^ w[i]):
				continue
			else:
				false_byte = True
				break
		if not false_byte:
			key.append(b)
			break

print(key)
for word in ciphertext:
	print(bytexor(key, word).decode('utf8'))
