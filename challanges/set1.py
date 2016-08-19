import base64
import string
from Crypto.Cipher import AES

def ch1():
    hexStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    decodedStr = hexStr.decode("hex")
    b64enc = base64.b64encode(decodedStr)
    print "set1challange2 (SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t expected):"
    print b64enc

def ch2(buf1="1c0111001f010100061a024b53535009181c", buf2="686974207468652062756c6c277320657965"):
    str1 = buf1.decode("hex")
    str2 = buf2.decode("hex")
    
    xored = getXored(str1, str2)
    
    encoded = xored.encode("hex")
    print "set1challange2 (746865206b696420646f6e277420706c6179 expected):"
    print encoded

def getXored(str1, str2):
    xored = ""
    for x, y in zip(str1, str2):
        xored = xored + chr(ord(x) ^ ord(y))
    return xored

def ch3(buf="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"):
    xoredStr = buf.decode("hex")
    candidate = findSingleCharXor(xoredStr)
    foundString = candidate[1]
    print foundString
    return foundString

def findSingleCharXor(xoredStr):
    strLen = len(xoredStr)
    
    candidateList = []
    for i in range(0, 128):
        singleCharString = ""
        currentChar = chr(i)
        for x in range(strLen):
            singleCharString = singleCharString + currentChar

        xored = ""
        for x, y in zip(xoredStr, singleCharString):
            xored = xored + chr(ord(x) ^ ord(y))
        
        charCount = 0
        for x in xored:
            if x in string.ascii_letters + " .,'*!?\n":
                charCount += 1
        candidateList.append((charCount, xored, currentChar))
    
    sortedList = sorted(candidateList, key=lambda x:x[0], reverse=True)
    firstcandidate = sortedList[0]
    return firstcandidate

def ch4():
    f = open("data/set1/4.txt", 'r')
    encryptedList = f.readlines()
    for i, encryptedString in enumerate(encryptedList):
        singleCharXored = ch3(str(encryptedString).strip())
        if singleCharXored is not "":
            print "found " + singleCharXored + " at line " + str(i)
            break

def ch5(stringToEncode="Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", key="ICE"):
    repeatingKey = ""
    while len(repeatingKey) < len(stringToEncode):
        repeatingKey = repeatingKey + key
    xored = ""
    for (x, y) in zip(stringToEncode, repeatingKey):
        xored = xored + chr(ord(x) ^ ord(y))
    encoded = xored.encode("hex")
    print encoded

def binHammingDistance(str1="this is a test", str2="wokka wokka!!!"):
    distance = 0
    for x, y in zip(str1, str2):
        bin1 = bin(ord(x))[2:]
        bin2 = bin(ord(y))[2:]
        while len(bin1) > len(bin2):
            bin2 = "0" + bin2
        while len(bin1) < len(bin2):
            bin1 = "0" + bin1
        for a, b in zip(bin1, bin2):
            if a != b:
                distance += 1
    if str1 == "this is a test" and str2 == "wokka wokka!!!":
        if distance == 37:
            print "woohoo binHammingDistance test successful"
            return 0
        else:
            print "binHammingDistance failed - distance:  %d (should be 37)" % distance
    return distance

def calckeysize(encryptedString):
    distances = []
    for key_size in range(2, 41):
        dist1 = binHammingDistance(encryptedString[0 : key_size], encryptedString[key_size : 2 * key_size])
        dist2 = binHammingDistance(encryptedString[2 * key_size : 3 * key_size], encryptedString[3 * key_size : 4 * key_size])
        dist3 = binHammingDistance(encryptedString[4 * key_size : 5 * key_size], encryptedString[5 * key_size : 6 * key_size])
        dist4 = binHammingDistance(encryptedString[6 * key_size : 7 * key_size], encryptedString[7 * key_size : 8 * key_size])
        dist5 = binHammingDistance(encryptedString[8 * key_size : 9 * key_size], encryptedString[9 * key_size : 10 * key_size])
        avg_norm_dist = float(dist1 + dist2 + dist3 + dist4 + dist5) / 5 / key_size
        # avg_norm_dist = float(dist1 + dist2) / 2 / key_size
        distances.append((key_size, avg_norm_dist))
    sorted_distances = sorted(distances, key=lambda x: x[1])[:3]
    print "top 3 (key_size, normalized distance) touples:"
    print sorted_distances


def ch6():
    binHammingDistance()
    
    f = open("data/set1/6.txt", 'r')
    encodedString = f.read()
    encryptedString = base64.b64decode(encodedString)
    
    calckeysize(encryptedString)
    # top 3 keysizes:
    # [(5, 2.68), (29, 2.6965517241379313), (15, 2.96)]
    # correct size is 29
    key_size = 29
    blocks = [encryptedString[i:i + key_size] for i in range(0, len(encryptedString), key_size)]
    
    transposed_blocks = []
    for i in range(key_size):
        transposed_blocks.append("".join([block[i] for block in blocks[:-1]]))
    
    key = ""
    for tblock in transposed_blocks:
        key += findSingleCharXor(tblock)[2]
    print "key is:\n%s" % key
    
    decryptedString = "".join([getXored(key, x) for x in blocks])
    print "decryptedString message is:\n%s" % decryptedString

def ch7():
    f = open("data/set1/7.txt", 'r')
    encodedCiphertext = f.read()
    ciphertext = base64.b64decode(encodedCiphertext)
    key = "YELLOW SUBMARINE"
    cipher = AES.new(key)
    decrypted_text = cipher.decrypt(ciphertext)
    print decrypted_text

def ch8():
    f = open("data/set1/8.txt", 'r')
    encodedCiphertexts = f.readlines()
    ciphertexts = [encoded.strip().decode("hex") for encoded in encodedCiphertexts]
    key_size = 16
    
    duplicates = []
    for text_index, text in enumerate(ciphertexts):
        unique_blocks = []
        duplicate_counter = 0
        blocks = [text[index:index + key_size] for index in range(0, len(text), key_size)]
        for block in blocks:
            if block in unique_blocks:
                duplicate_counter += 1
            else:
                unique_blocks.append(block)
        
        duplicates.append((text_index, duplicate_counter))
    
    sorted_duplicates = sorted(duplicates, key=lambda x : x[1], reverse=True)[:3]
    print "top 3 (line, duplicate_count):"
    print sorted_duplicates

def init():
    choice = raw_input("enter [1-8] to select challange: ")
    methodSwitcher = {
        "1": ch1,
        "2": ch2,
        "3": ch3,
        "4": ch4,
        "5": ch5,
        "6": ch6,
        "7": ch7,
        "8": ch8,
    }
    methodSwitcher.get(choice, ch8)()

init()
