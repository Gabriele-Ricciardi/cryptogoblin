import pytest
import cryptogoblin as cg

def test_PKCS7():
    #Cryptopals Set 2 Challenge 9
    assert cg.pad(b'YELLOW SUBMARINE', 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'

def test_AESCBC():
    #Cryptopals Set 2 Challenge 10
    with open('./set_2/10.txt', encoding="utf-8") as f:
        cipher = ''.join([cg.base64ToHex(line.rstrip('\n')) for line in f])

    with open('./set_1/7_decrypted.txt', encoding='utf-8') as d:
        plain = ''.join(list(d))

    x = cg.AES_128('YELLOW SUBMARINE'.encode())
    IV = b'\x00'*16
    assert(x.decrypt(bytes.fromhex(cipher),'CBC', IV).decode() == plain)

def test_detectionECBCBCOracle():
    #Cryptopals Set 2 Challenge 11
    oracle = cg.ECBCBCOracle()
    assert(cg.detectECBCBCOracle(oracle) == oracle.encMet)