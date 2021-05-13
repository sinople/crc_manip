import itertools
import random

# By Sinople 
# Initially inspired by
# https://rosettacode.org/wiki/CRC-32#Python
# More details can be found on my blog at
# https://www.sinopleblog.com/crc-is-not-cryptography.html


class CRC:
    '''
    This CRC class works to generate crc of length multiple of 8.
    :param polynome int: polynome in reciprocal form
    :param init_xor int: first data xoring to apply on the data
    :param end_xor int: final data xoring to apply on the data
    '''
    def __init__(self, polynome, init_xor, end_xor):
        self.polynome = polynome
        self.crc_len = (len(hex(polynome)[2:])-1)//2
        self.init_xor = init_xor
        self.end_xor = end_xor
        self.crc_table = self.create_table()
        self.inv_crc_table = self.create_inv_table()

    def create_table(self):
        table = []
        for i in range(256): # for all byte value
            k = i
            for j in range(8): # compute modulus
                if k & 1:
                    k ^= self.polynome
                k >>= 1
            table.append(k)
        return table

    def create_inv_table(self):
        inv_table = [0] * 256
        l = self.crc_len*8 - 8 # /!\
        for i, elem in enumerate(self.crc_table):
            val = elem >> l
            inv_table[val] = i
        return inv_table

    def convert_polynome(self, from_type, to_type):
        raise NotImplementedError()

    def crc(self, bytestring, crc_val=0):
        '''
        compute crc value of a bytestring with an initial crc value
        '''
        crc_val ^= self.init_xor
        for byte in bytestring:
            crc_val = (crc_val >> 8) ^ self.crc_table[(crc_val & 0xff) ^ byte]
        return crc_val ^ self.end_xor

    def crc_inv_bf(self, crc_target):
        '''
        Create custom data for a custom crc value by testing all possible values
        '''
        for val in itertools.product(range(256), range(256), range(256), range(256)):
            bytestring = bytes(val)
            if crc_update(bytestring, 0) == crc_target:
                return bytestring

    def crc_inv(self, data, crc_target):
        '''
        Create custom data for a custom crc value by reversing crc calculus
        :param data bytestring: data to which some bytes will be added to have specific crc value
        :param crc_target int: expected crc of output data
        :retun bytestring: new data with crc equal to crc_target
        '''
        original_crc = self.crc(data, 0)
        prev_crc = crc_target ^ self.end_xor 
        index_table = []
        crc_list = [prev_crc]
        new_data = []
        l = self.crc_len*8 - 8
        # Computation of higher part of CRC 
        # and find corresponding element in table
        for i in range(self.crc_len):
            crc_head = prev_crc >> l
            index = self.inv_crc_table[crc_head]
            index_table = [index] + index_table
            prev_crc = (prev_crc ^ self.crc_table[index]) << 8
            crc_list = [prev_crc] + crc_list
        crc_list = [original_crc ^ self.init_xor] + crc_list
        # computation lower part of crc
        # and of expected data
        for i in range(self.crc_len):
            new_data.append((crc_list[i] ^ index_table[i]) & 0xFF)
            crc_list[i+1] = (crc_list[i] >> 8) ^ (self.crc_table[index_table[i]])
        return data + bytes(new_data)

def test(polynome):
    msg = b"The quick brown fox jumps over the lazy dog"
    crc = CRC(polynome, 0, 0) #int("FF"*8, 16), int("FF"*8, 16))
    l = (len(hex(polynome)[2:])-1)//2
    crc_target = int("deadbeef"[-2*l:], 16)
    crc_inv = crc.crc_inv(msg, crc_target)
    crc_val =  crc.crc(crc_inv, 0) 
    assert crc.crc(crc_inv, 0) == crc_target, hex(crc_val)

def test_all():
    test(0x1db710640) #32
    print("[DONE] 32 done")
    test(0x105EC76F1)  #32C
    print("[DONE] 32C done")
    test(0x1B000000000000001) #64-iso
    print("[DONE] 364ISO done")
    test(0x192D8AF2BAF0E1E85) #64-cma
    print("[DONE] 364CMA done")
    test(0x1E9) #
    print("[DONE] crc8 autosar")

def cipher_attack(cipher, modified_cipher):
    # can be adapt with any crc but too lazy
    crc = CRC(0x1db710640, int('FF'*4, 16), int('FF'*4, 16))
    otp = lambda x,k:bytes([a^b for a,b in zip(x, k)])
    key = otp(cipher, modifified_cipher)
    key = crc.crc_inv(key_2, crc.crc(b'\x00'*len(message)))
    pass

def test_cipher_attack(data):
    cipher = lambda x,k:bytes([a^b for a,b in zip(x, k)])
    crc = CRC(0x1db710640, int('FF'*4, 16), int('FF'*4, 16))
    message = data
    key     = random.randbytes(len(message))
    c = cipher(message, key)
    crc_m = crc.crc(message)
    key_2 = b'\x42' * (len(message) - 4)
    key_2 = crc.crc_inv(key_2, crc.crc(b'\x00'*len(message)))
    modified_c = cipher(c, key_2)
    modified_m = cipher(modified_c, key)
    print("key", key)
    print("key_2", key_2)
    print("message", message)
    print("cipher", c)
    print("new ciphered", modified_c)
    print("new message", modified_m)
    print("crc message    ", crc_m)
    print("crc new message", crc.crc(modified_m))
    assert crc.crc(modified_m) == crc_m

    



if __name__ == '__main__':
    test_all()
    test_cipher_attack(b'CRC is easy to break do not use it')


# TODO argparse one day if I'm not lazy

