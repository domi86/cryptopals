import base64
from Crypto.Cipher import AES

def ch9(input_string = "YELLOW SUBMARINE"):
    while len(input_string) < 20:
        input_string = input_string + "\x04"
    print input_string
    print "length: %d (should be 20)" % len(input_string)

def ch10():
    f = open("data/set2/10.txt", 'r')
    encodedCiphertext = f.read()
    ciphertext = base64.b64decode(encodedCiphertext)
    key = "YELLOW SUBMARINE"
    decrypted_text = cbc_decrypt(ciphertext, key)
    print decrypted_text

def cbc_decrypt(ciphertext, key, iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"):
    block_size = 16
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    result = ""
    previousBlock = iv
    for block in blocks:
        ecbdecrypted = ecb_decrypt_block(block, key)
        xored = bin_xor(ecbdecrypted, previousBlock)
        previousBlock = block
        result = result + xored
    return result

def ecb_encrypt_block(text, key):
    cipher = AES.new(key)
    encrypted = cipher.encrypt(text)
    return encrypted

def ecb_decrypt_block(ciphertext, key):
    cipher = AES.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def bin_xor(str1, str2):
    xored = ""
    for x, y in zip(str1, str2):
        xored = xored + chr(ord(x) ^ ord(y))
    return xored

def ch11():
    print "try later"

def ch12():
    print "try later"

def ch13():
    print "try later"

def ch14():
    print "try later"

def ch15():
    print "try later"

def ch16():
    print "try later"


def init():
    choice = raw_input("enter [9-16] to select challange: ")
    methodSwitcher = {
        "9": ch9,
        "10": ch10,
        "11": ch11,
        "12": ch12,
        "13": ch13,
        "14": ch14,
        "15": ch15,
        "16": ch16,
    }
    methodSwitcher.get(choice, ch10)()

init()