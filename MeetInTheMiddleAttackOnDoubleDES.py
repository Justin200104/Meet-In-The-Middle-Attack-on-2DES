# Assignment 1 - MITM Attack on 2DES
# Name: Justin Langevin
# Student Number: 8648380
# Date: 2024-05-30
# Description: This program preforms a meet-in-the-middle attack on 2DES. The program takes in a known key1, a known suffix, 
# and a set of plaintexts and ciphertexts. The program generates all possible 3-byte keys and builds a middle table with the decryptions 
# of the ciphertexts using key2. The program then checks if any encrypted plaintext using known_key1 matches the decrypted values in the middle table. 
# If a match is found, the program returns key2. If no match is found, the program returns None.

from itertools import product
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

#Function to generate all possible 3-byte key combinations
def generate_keys():
    keys = [bytes(k) for k in product(range(256), repeat=3)]
    return keys

#Function to perform DES encryption
def des_encrypt(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    paddedData = pad(data, DES.block_size)
    return cipher.encrypt(paddedData)

#Function to perform DES decryption
def des_decrypt(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(data)
    try:
        return unpad(decrypted_data, DES.block_size)
    except ValueError:
        return decrypted_data

#Man-in-the-Middle attack
def manInTheMiddleAttack(suffix, known_key1, plaintexts, ciphertexts):
    ThreeByteKeys = generate_keys()
    middleTable = {}

    #Build the middleTable with decryptions of the ciphertexts using key2
    for threeByteKey in ThreeByteKeys:
        key2 = threeByteKey + suffix
        decrypted = des_decrypt(key2, ciphertexts[0])
        middleTable[decrypted] = key2
        decrypted = des_decrypt(key2, ciphertexts[1])
        middleTable[decrypted] = key2
        decrypted = des_decrypt(key2, ciphertexts[2])
        middleTable[decrypted] = key2
    
    # Debug: print the size of middleTable
    print(f"Middle Table size: {len(middleTable)}")

    #Check if any encrypted plaintext using known_key1 matches the decrypted values in middleTable
   
    encrypted = des_encrypt(known_key1, plaintexts[0])
    print(f"Encrypted: {encrypted.hex()}")
    if encrypted in middleTable:
        encryptedTwo = des_encrypt(known_key1, plaintexts[1])
        encryptedThree = des_encrypt(known_key1, plaintexts[2])
        print(f"Encrypted: {encryptedTwo.hex()}")
        print(f"Encrypted: {encryptedThree.hex()}")

    if encryptedTwo in middleTable and encryptedThree in middleTable:
        key2 = middleTable[encrypted]
        print(f"Plaintext: {plaintexts[0]}")
        print(f"Plaintext: {plaintexts[1]}")
        print(f"Plaintext: {plaintexts[2]}")
        print(f"Key1: {known_key1}")
        print(f"Key2: {key2}")
        return known_key1, key2
    else:
        print(f"Plaintext: not found in")

    print("Key2 not found")
    return None

#Example keys and known suffix
known_key1 = b'abcdefgh'
suffixKey2 = b'xkrmd'

#Known plaintexts and ciphertexts
plaintexts = [
    b'hello world',
    b'applied cryptography',
    b'alice bob'
]

ciphertexts = [
    b'\x90\xa2\x94\xf0\xd1\xe4\x9f@\x85L\xa4_\r\xce\x8e\xb2\x93\x96N\xd3\xc5\xb8\xc2\xa2',
    b'\x1f\xe2\xf1\x8e\xafuJ/\xe6\xde\xf8H\xbb\xb1\xbe\x95\xf2c#\xaa\xde\xd1\x04\x85\x93\x96N\xd3\xc5\xb8\xc2\xa2',
    b'e\xca\x9379G\x8a{\x87O\xf4\x9d\xaan\x03\xf5\x93\x96N\xd3\xc5\xb8\xc2\xa2'
]

# Perform the MITM attack
manInTheMiddleAttack(suffixKey2, known_key1, plaintexts, ciphertexts)