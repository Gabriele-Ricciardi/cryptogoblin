def hexToBase64(hx: str) -> str:
    #Base64 chars as in RFC 4648
    chars = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/','=']
    
    #check for 24-bits padding
    pad = (3 - len(bytes.fromhex(hx)) % 3) % 3
    hx += '00'*pad
    
    #convert hex to bytes
    b8 = bytes.fromhex(hx)
    
    #create empty list to contain 6 bits values
    b6 = [0]*(len(b8)//3)*4
    
    #distribute 24 bits in 4 6-bits variables
    for j,i in zip(range(0,len(b6),4), range(0, len(b8), 3)):
        b6[j] = b8[i] >> 2
        b6[j+1] = ((b8[i] & 3) << 4) ^ (b8[i+1] >> 4)
        b6[j+2] = ((b8[i+1] & 15) << 2) ^ (b8[i+2] >> 6)
        b6[j+3] = b8[i+2] & 63
    
    #padding
    while pad:
        b6[-pad] = 64
        pad -= 1
    
    #use 6-bits vars as indices for Base64 chars table
    rst = ''.join([chars[i] for i in b6])
    
    return(rst)

def base64ToHex(b: str) -> str:
    #Base64 chars as in RFC 4648
    chars = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/','=']

    blocks = ''
    b6 = []
    hx = ''
    pad = 0
    #split base64 into 24-bit blocks
    for i in range(0, len(b), 4):
        blocks = (b[i:i+4])
        b6 = []
        b8 = []

        #reverse Base64 table by finding indices of chars
        for c in blocks:
            b6.append(chars.index(c))

        #count padding and set bits to 0
        while 64 in b6:
            pad += 1
            b6[b6.index(64)] = 0
        
        #distribute 24 bits in 3 bytes
        b8.append((b6[0] << 2) ^ (b6[1] >> 4))
        b8.append(((b6[1] & 15) << 4) ^ (b6[2] >> 2))
        b8.append(((b6[2] & 3) << 6) ^ b6[3])

        #return hex string
        hx += ''.join(bytes(b8).hex())
    #remove padding
    if pad:
        hx = hx[:-pad*2]
    
    return(hx)

def fixedXOR(a: bytes, b: bytes) -> bytes:
    #bit by bit XOR combination of 2 equal-length array of bytes
    return bytes([ab^bb for ab, bb in zip(a, b)])

def bestFreq(p: list, d=None) -> int:
    #if no freq dictionary is provided, use English
    if d is None:
        d = {
            b'A': 0.0651738,
            b'B': 0.0124248,
            b'C': 0.0217339,
            b'D': 0.0349835,
            b'E': 0.1041442,
            b'F': 0.0197881,
            b'G': 0.0158610,
            b'H': 0.0492888,
            b'I': 0.0558094,
            b'J': 0.0009033,
            b'K': 0.0050529,
            b'L': 0.0331490,
            b'M': 0.0202124,
            b'N': 0.0564513,
            b'O': 0.0596302,
            b'P': 0.0137645,
            b'Q': 0.0008606,
            b'R': 0.0497563,
            b'S': 0.0515760,
            b'T': 0.0729357,
            b'U': 0.0225134,
            b'V': 0.0082903,
            b'W': 0.0171272,
            b'X': 0.0013692,
            b'Y': 0.0145984,
            b'Z': 0.0007836,
            b' ': 0.1918182  # Space character frequency
        }

    #convert bytes string to list
    bp = [pi for pi in p]
    score = [0]*len(bp)
    count = dict(d)

    #for each plaintext
    for i in range(len(bp)):
        sds = 0

        #for each character in dictionary
        for c in d.keys():

            #count each character
            count[c] = bp[i].upper().count(c)

            #compare char freq. Lower is better
            sds += (d[c] - count[c]/len(bp[i]))

        #limit score between 0 and 1
        score[i] = max(0, 1 - sds)

    #pick best frequency matching plaintext
    return(score.index(max(score)))

def singleByteXOR(a: bytes) -> list:
    plain = ['']*255

    #calculate XOR with each key
    for k in range(255):
        cipher = bytes([k]*len(a))
        plain[k] = fixedXOR(a, cipher)

    #pick best English letter frequency matching plaintext
    bestKey = bestFreq(plain)

    #return best key and best plaintext
    return [bestKey, plain[bestKey]]

def detectSingleByteXOR(a: list) -> bytes:
    #get best plaintext for each cipher
    bestPlains = [singleByteXOR(b)[1] for b in a]

    #return most fitting plaintext
    return(bestPlains[bestFreq(bestPlains)])

def repeatingKeyXOR(bk: bytes, bp: bytes) -> bytes:
    trail = len(bp) % len(bk)

    #compute key stream
    keyStream = bk*(len(bp)//len(bk)) + bk[0:trail]
    return(fixedXOR(bp, keyStream))

def hammingDistance(a: bytes, b: bytes) -> int:
    dist = 0

    #each flipped bit after byte XOR is a differing bit
    for ba,bb in zip(a, b):
        dist += (ba ^ bb).bit_count()

    #return sum of flipped bits
    return dist

def breakRepeatingKeyXOR(bc: bytes, keySize: int =None) -> list:
    cSize = len(bc)
    hamDistAvgs = []

    #if key size is known, use it, else test from 2 to 40
    if keySize == None:
        keySize = list(range(2, min(40, cSize//4), 1))
    else:
        keySize = [keySize]

    #for each key size
    for ks in keySize:
        hamSum = 0
        block = []

        #take first 4 key-sized blocks
        for i in range(0, ks*4, ks):
            block.append(bc[i:i+ks])

        #compute average of Hamming distance for all combinations of 4 key-sized blocks
        hamSum += hammingDistance(block[0], block[1])/ks
        hamSum += hammingDistance(block[0], block[2])/ks
        hamSum += hammingDistance(block[0], block[3])/ks
        hamSum += hammingDistance(block[1], block[2])/ks
        hamSum += hammingDistance(block[1], block[3])/ks
        hamSum += hammingDistance(block[2], block[3])/ks
        hamDistAvgs.append(hamSum / 6)  

    #pick key with lowest Hamming distance
    bestKeySize = keySize[hamDistAvgs.index(min(hamDistAvgs))]

    #break cipher into key-sized blocks
    block = []
    blockTransposed = [[] for i in range(bestKeySize)]
    bestKey = []

    #in case cSize % bestKeySize !=0, some trailing bytes are left out
    #this should not matter to retrieve the XOR key
    for bi in range(0, cSize-bestKeySize+1, bestKeySize):
        block.append(bc[bi:bi+bestKeySize])
        for ki in range(bestKeySize):
            blockTransposed[ki].append(block[-1][ki])
  
    #transpose blocks into key-size number of blocks
    for ki in range(bestKeySize):
        blockTransposed[ki] = bytes(blockTransposed[ki])

        #find best English fitting single-byte XOR key for each transposed block
        bestKey.append(singleByteXOR(blockTransposed[ki])[0])

    #convert bestKey bytes into hex
    bestKey = bytes(bestKey)

    #return key and plaintext of cipher in hex encoding
    return(bestKey, repeatingKeyXOR(bestKey, bc))

#PKCS#7 as defined in RFC 5652, section 6.3
#https://tools.ietf.org/html/rfc5652#section-6.3
#k < 256
def pad(s: bytes, k: int =None) -> bytes:
    #128 bit by default
    if k == None:
        k = 16
    
    #number of bytes to pad
    p = k - (len(s) % k)

    #padding string
    pd = bytes([p] * p)

    #return original string with padding
    return(s + pd)


#AES as defined in FIPS 197
#https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
class AES_128:

    _sBox = [
        [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
        [202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192],
        [183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21],
        [4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117],
        [9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132],
        [83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207],
        [208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168],
        [81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210],
        [205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115],
        [96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219],
        [224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121],
        [231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8],
        [186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138],
        [112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158],
        [225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223],
        [140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]]
    
    _invSBox = [
        [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251],
        [124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203],
        [84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78],
        [8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37],
        [114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146],
        [108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132],
        [144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6],
        [208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107],
        [58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115],
        [150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110],
        [71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27],
        [252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244],
        [31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95],
        [96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239],
        [160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97],
        [23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125]]
    
    _keySize = 16
    _nK = 4

    # +++ PUBLIC METHODS +++
    
    def __init__(self, k: bytes):
        self.key = k
        self.rounds = 10

        #generate round keys
        self.roundKeys = self._keyExpansion()

    def encrypt(self, pb: bytes, modOp: str = None) -> bytes:

        match modOp:
            case 'ECB':
                return self._encipherECB(pb)
            case 'None':
                return self._encipher(pb)
            
    def decrypt(self, cb: bytes, modOp: str = None) -> bytes:

        match modOp:
            case 'ECB':
                return self._decipherECB(cb)
            case 'None':
                return self._decipher(cb)
            
    # +++ MODES OF OPERATION +++

    #As defined in NIST SP 800-38A
    #https://csrc.nist.gov/pubs/sp/800/38/a/final
    def _encipherECB(self, pb: bytes) -> bytes:
        ppb = pad(pb)
        nBlocks = len(ppb)//16
        blocks = [self._encipher(ppb[i*16:i*16+16]) for i in range(nBlocks)]
        return b''.join(blocks)

    def _decipherECB(self, cb: bytes) -> bytes:
        nBlocks = len(cb)//16
        blocks = [self._decipher(cb[i*16:i*16+16]) for i in range(nBlocks)]

        #remove padding
        padding = blocks[-1][-1]
        blocks = blocks[:-1] + [blocks[-1][:-padding]]

        return b''.join(blocks)

    # +++ INTERNAL FUNCTIONS +++

    def _encipher(self, pb: bytes) -> bytes:
        state = [[0 for c in range(4)] for r in range(4)]
        out = [0] * 16

        #copy input array into state array
        for r in range(4):
            for c in range(4):
                state[r][c] = pb[r+4*c]

        #add first round key
        state = self._addRoundKey(state, 0)

        #round 1 to 9
        for round in range(self.rounds -1):
            state = self._subBytes(state)
            state = self._shiftRows(state)
            state = self._mixColumns(state)
            state = self._addRoundKey(state, round+1)

        #last round
        state = self._subBytes(state)
        state = self._shiftRows(state)
        state = self._addRoundKey(state, self.rounds)

        #copy state array into output array
        for r in range(4):
            for c in range(4):
                out[r+4*c] = state[r][c]

        return bytes(out)
    
    def _decipher(self, cb: bytes) -> bytes:
        state = [[0 for c in range(4)] for r in range(4)]
        out = [0] * 16

        #copy input array into state array
        for r in range(4):
            for c in range(4):
                state[r][c] = cb[r+4*c]

        #remove last round key
        state = self._addRoundKey(state, 10)

        #round 9 to 1
        for round in range(self.rounds -1, 0, -1):
            state = self._invShiftRows(state)
            state = self._invSubBytes(state)
            state = self._addRoundKey(state, round)
            state = self._invMixColumns(state)
        
        #round 0
        state = self._invShiftRows(state)
        state = self._invSubBytes(state)
        state = self._addRoundKey(state, 0)

        #copy state array into output array
        for r in range(4):
            for c in range(4):
                out[r+4*c] = state[r][c]

        return bytes(out)

    def _subBytes(self, s):

        #substitute each bytes with SBox
        for r in range(4):
            for c in range(4):
                #first letter of hex, i.e. most significant 4 bits
                x = s[r][c] >> 4
                #second letter of hex, i.e. least significant 4 bits
                y = s[r][c] & 15
                s[r][c] = self._sBox[x][y]
        return s
    
    def _invSubBytes(self, s):

        #substitute each bytes with invSBox
        for r in range(4):
            for c in range(4):
                #first letter of hex, i.e. most significant 4 bits
                x = s[r][c] >> 4
                #second letter of hex, i.e. least significant 4 bits
                y = s[r][c] & 15
                s[r][c] = self._invSBox[x][y]
        return s
    
    def _shiftRows(self, s):
        for r in range(4):
            for ri in range(r):
                s[r] = s[r][1:] + s[r][:1]
        return s
    
    def _invShiftRows(self, s):
        for r in range(4):
            for ri in range(r):
                s[r] = s[r][-1:] + s[r][:-1]
        return s
    
    def _mixColumns(self, s):
        s_tmp = [[0 for c in range(4)] for r in range(4)]

        #matrix multiplication
        for c in range(4):
            s_tmp[0][c] = self._xTimes(s[0][c]) ^ (self._xTimes(s[1][c])^s[1][c]) ^ s[2][c] ^ s[3][c]
            s_tmp[1][c] = s[0][c] ^ (self._xTimes(s[1][c])) ^ (self._xTimes(s[2][c])^s[2][c]) ^ s[3][c]
            s_tmp[2][c] = s[0][c] ^ s[1][c] ^ (self._xTimes(s[2][c])) ^ (self._xTimes(s[3][c]) ^ s[3][c])
            s_tmp[3][c] = (self._xTimes(s[0][c]) ^ s[0][c]) ^ s[1][c] ^ s[2][c] ^ (self._xTimes(s[3][c]))
        
        return s_tmp
    
    def _invMixColumns(self,s):
        s_tmp = [[0 for c in range(4)] for r in range(4)]

        #inverse matrix multiplication
        for c in range(4):
            s_tmp[0][c] = self._0eTimes(s[0][c]) ^ self._0bTimes(s[1][c]) ^ self._0dTimes(s[2][c]) ^ self._09Times(s[3][c])
            s_tmp[1][c] = self._09Times(s[0][c]) ^ self._0eTimes(s[1][c]) ^ self._0bTimes(s[2][c]) ^ self._0dTimes(s[3][c])
            s_tmp[2][c] = self._0dTimes(s[0][c]) ^ self._09Times(s[1][c]) ^ self._0eTimes(s[2][c]) ^ self._0bTimes(s[3][c])
            s_tmp[3][c] = self._0bTimes(s[0][c]) ^ self._0dTimes(s[1][c]) ^ self._09Times(s[2][c]) ^ self._0eTimes(s[3][c])

        return s_tmp
    
    def _addRoundKey(self, s, rnd):

        #add round key to state
        for c in range(4):
            for r in range(4):
                s[r][c] = s[r][c] ^ self.roundKeys[4*rnd+c][r]
        
        return s
    
    def _subWord(self, w):
        tmp = []
        for i in range(4):
        #first letter of hex, i.e. most significant 4 bits
            x = w[i] >> 4
        #second letter of hex, i.e. least significant 4 bits
            y = w[i] & 15
            tmp.append(self._sBox[x][y])
        
        return bytes(tmp)
    
    def _rotWord(self, w):
        return w[1:]+w[:1]

    def _keyExpansion(self):

        #round constants
        rCon = [[1,0,0,0]]
        for r in range(self.rounds - 1):
            rCon.append([self._xTimes(rCon[-1][0]), 0,0,0])

        #first Nk words of the expanded key are the key itself
        w = [self.key[4*i:4*i+4] for i in range(self._nK)]

        #compute next words, see Algorithm 2
        for i in range(self._nK, (self.rounds+1) * 4, 1):
            tmp = w[i-1]

            #if i is a multiple of Nk
            if (i % self._nK == 0):
                tmp = self._XOR(self._subWord(self._rotWord(tmp)), rCon[i//self._nK -1])
                   
            #only needed for AES-256. Here for later development
            elif (self._nK > 6) and (i % self._nK == 4):
                tmp = self._subWord(tmp)
        
            w.append(self._XOR(w[i-4], tmp))

        return w
    
    #+++ BYTES OPERATIONS +++

    def _XOR(self, a, b):
        #bit by bit XOR
        return bytes([ab^bb for ab, bb in zip(a, b)])
    
    #multiplication with x, see Section 4.2
    def _xTimes(self, b):
        res = 0
        if b & 128:
            res = ((b & 127) << 1) ^ 27
        else:
            res = (b & 127) << 1
        return res
    
    def _04Times(self, b):
        return self._xTimes(self._xTimes(b))
    
    def _08Times(self, b):
        return self._xTimes(self._04Times(b))
    
    def _09Times(self, b):
        return b ^ self._08Times(b)
    
    def _0bTimes(self, b):
        return self._08Times(b) ^ self._xTimes(b) ^ b
    
    def _0dTimes(self, b):
        return self._08Times(b) ^ self._04Times(b) ^ b
    
    def _0eTimes(self, b):
        return self._08Times(b) ^ self._04Times(b) ^ self._xTimes(b)


def detectECB(c: bytes) -> list:
    candidates = []

    #for each cipher, split cipher in blocks of 16 bytes
    for cipher in c:
        nBlocks = len(cipher)//16
        blocks = [cipher[i*16:i*16+16] for i in range(nBlocks)]

        #for each block, test if block has duplicates inside cipher
        for b in blocks:
            tmp = blocks[:]
            tmp.remove(b)
            if b in tmp:
                candidates.append(cipher)
                break
    
    return candidates