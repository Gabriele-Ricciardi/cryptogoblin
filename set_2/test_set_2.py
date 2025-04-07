import pytest
import cryptogoblin as cg

def test_PKCS7():
    #Cryptopals Set 2 Challenge 9
    assert cg.pad(b'YELLOW SUBMARINE', 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'
