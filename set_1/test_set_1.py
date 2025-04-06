import pytest
import cryptogoblin as cg

def test_hexToBase64():
    #Cryptopals Set 1 Challenge 1
    assert cg.hexToBase64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d') == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

def test_fixedXOR():
    #Cryptopals Set 1 Challenge 2
    assert cg.fixedXOR(bytes.fromhex('1c0111001f010100061a024b53535009181c'),bytes.fromhex('686974207468652062756c6c277320657965')) == bytes.fromhex('746865206b696420646f6e277420706c6179')

def test_singleByteXor():
    #Cryptopals Set 1 Challenge 3
    assert cg.singleByteXOR(bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')) == [88, "Cooking MC's like a pound of bacon".encode()]

def test_detectSingleByteXOR():
    #Cryptopals Set 1 Challenge 4
    ciphers = []
    with open('./set_1/4.txt', encoding="utf-8") as f:
        ciphers = [bytes.fromhex(line.rstrip('\n\r')) for line in f]
    assert(cg.detectSingleByteXOR(ciphers) == 'Now that the party is jumping\n'.encode())

def test_repeatingKeyXOR():
    #Cryptopals Set 1 Challenge 5
    key = 'ICE'.encode()
    plain = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".encode()
    assert(cg.repeatingKeyXOR(key,plain) == bytes.fromhex('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'))

def test_breakRepeatingKeyXOR():
    #Cryptopals Set 1 Challenge 6

    a = 'this is a test'.encode()
    b = 'wokka wokka!!!'.encode()
    assert(cg.hammingDistance(a,b) == 37)


    with open('./set_1/6.txt', encoding="utf-8") as f:
        cipher = b''.join([bytes.fromhex(cg.base64ToHex(line.rstrip('\n'))) for line in f])
    
    with open('./set_1/6_decrypted.txt', encoding='utf-8') as d:
        plain = ''.join(list(d))

    res = cg.breakRepeatingKeyXOR(cipher)
    correctKey = (res[0] == 'Terminator X: Bring the noise'.encode())
    correctPlain = (res[1] == plain.encode())
    assert(correctKey and correctPlain)

def test_AESECB():
    #Cryptopals Set 1 Challenge 7
    with open('./set_1/7.txt', encoding="utf-8") as f:
        cipher = ''.join([cg.base64ToHex(line.rstrip('\n')) for line in f])

    with open('./set_1/7_decrypted.txt', encoding='utf-8') as d:
        plain = ''.join(list(d))

    x = cg.AES_128('YELLOW SUBMARINE'.encode())
    assert(x.decrypt(bytes.fromhex(cipher),'ECB').decode() == plain)

def test_detectECB():
    with open('./set_1/8.txt', encoding="utf-8") as f:
        cipher = [bytes.fromhex(line.rstrip('\n')) for line in f]

    assert(cg.detectECB(cipher)[0] == bytes.fromhex('d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a'))
