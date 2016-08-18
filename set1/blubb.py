import base64
import string

def s1ch1():
    hexStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    decodedStr = hexStr.decode("hex")
    b64enc = base64.b64encode(decodedStr)
    print "set1challange2 (SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t expected):"
    print b64enc

def s1ch2(buf1 = "1c0111001f010100061a024b53535009181c", buf2 = "686974207468652062756c6c277320657965"):
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

def s1ch3(buf = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"):
    xoredStr = buf.decode("hex")
    candidate = findSingleCharXor(xoredStr)
    foundString = candidate[1]
    print foundString
    return foundString

def findSingleCharXor(xoredStr):
    strLen = len(xoredStr)
    
    candidateList = []
    for i in range(0,128):
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
        
        if False:
            candidateList.append((charCount, xored, chr(i)))
        candidateList.append((charCount, xored, chr(i)))
        
    
    sortedList = sorted(candidateList, key=lambda x:x[0], reverse=True)
    firstcandidate = sortedList[0]
    return firstcandidate

def s1ch4():
    f = open("4.txt", 'r')
    encryptedList = f.readlines()
    for i, encryptedString in enumerate(encryptedList):
        singleCharXored = s1ch3(str(encryptedString).strip())
        if singleCharXored is not "":
            print "found " + singleCharXored + " at line " + str(i)
            break

def s1ch5(stringToEncode = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", key = "ICE"):
    repeatingKey = ""
    while len(repeatingKey) < len(stringToEncode):
        repeatingKey = repeatingKey + key
    xored = ""
    for (x, y) in zip(stringToEncode, repeatingKey):
        xored = xored + chr(ord(x) ^ ord(y))
    encoded = xored.encode("hex")
    print encoded

def binHammingDistance(str1 = "this is a test", str2 = "wokka wokka!!!"):
    diffCount = 0
    for x, y in zip(str1, str2):
        bin1 = bin(ord(x))[2:]
        bin2 = bin(ord(y))[2:]
        while len(bin1) > len(bin2):
            bin2 = "0" + bin2
        while len(bin1) < len(bin2):
            bin1 = "0" + bin1
        for a, b in zip(bin1, bin2):
            if a != b:
                diffCount += 1
    if str1 == "this is a test" and str2 == "wokka wokka!!!":
        if diffCount == 37:
            print "woohoo test successful"
            return 0
        else:
            print "try again - counter: " + diffCount
    return diffCount

def calckeysize(encryptedString):
    distances = []
    for key_size in range(2, 41):
        dist1 = binHammingDistance(encryptedString[0 : key_size], encryptedString[key_size : 2 * key_size])
        dist2 = binHammingDistance(encryptedString[2 * key_size : 3 * key_size], encryptedString[3 * key_size : 4 * key_size])
        dist3 = binHammingDistance(encryptedString[4 * key_size : 5 * key_size], encryptedString[5 * key_size : 6 * key_size])
        dist4 = binHammingDistance(encryptedString[6 * key_size : 7 * key_size], encryptedString[7 * key_size : 8 * key_size])
        dist5 = binHammingDistance(encryptedString[8 * key_size : 9 * key_size], encryptedString[9 * key_size : 10 * key_size])
        avg_norm_dist = float(dist1 + dist2 + dist3 + dist4 + dist5) / 5 / key_size
        #avg_norm_dist = float(dist1 + dist2) / 2 / key_size
        distances.append((key_size, avg_norm_dist))
    sorted_distances = sorted(distances, key=lambda x: x[1])[:3]
    print sorted_distances
    return sorted_distances[0][1]


def s1ch6():
    #binHammingDistance()
    # working
    
    f = open("6.txt", 'r')
    encodedString = f.read()
    encryptedString = base64.b64decode(encodedString)
    
    #calckeysize(encryptedString)
    # working, result:
    # [(5, 2.68), (29, 2.6965517241379313), (15, 2.96)]
    # correct size is 29
    key_size = 29
    blocks = [encryptedString[i:i+key_size] for i in range(0, len(encryptedString), key_size)]
    
    transposed_blocks = []
    for i in range(key_size):
        moo = [block[i] for block in blocks[:-1]]
        transposed_blocks.append("".join(moo))
    
    key = ""
    for tblock in transposed_blocks:
        moo = findSingleCharXor(tblock)
        key += moo[2]
    
    print "key is '%s'" % key
    
    decrypted = "".join([getXored(key, x) for x in blocks])
    
    print "decrypted message is:"
    print decrypted

#s1ch1()
#s1ch2()
#s1ch3()
#s1ch4()
#s1ch5()
s1ch6()
