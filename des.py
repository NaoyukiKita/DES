#!/usr/bin/env python
# coding: utf-8

# In[1]:


import os

import numpy as np
import pandas as pd

class DES():
    def __init__(self, key):
        self.des_key_bin = self.__hex_to_bin(key)
        if self.des_key_bin.shape[0] != 64:
            print('ERROR: key should be a 16-digit hexadecimal number.')
            return
        self.IP = self.__load_array('./Initial_permutaion/IP.csv')
        self.IP_inv = self.__load_array('./Initial_permutaion/IP_inv.csv')
        self.PC1 = self.__load_array('./PC/PC1.csv')
        self.PC2 = self.__load_array('./PC/PC2.csv')
        self.E = self.__load_array('./Internal_block_cipher/E.csv')
        self.P = self.__load_array('./Internal_block_cipher/P.csv')
        self.S = np.zeros((8, 4, 16))
        for i in range(8):
            path = f'Internal block cipher/S-boxes/S-{i + 1}.csv'
            self.S[i] = np.array(pd.read_csv(path, header=None, dtype=int).values)
        self.values = [1] * 16
        for i in range(16):
            if i in {1, 2, 9, 16}: continue
            self.values[i] = 2

        return
    
    def encrypt(self, plain):
        plain_bin = self.__hex_to_bin(plain)
        if plain_bin.shape[0] != 64:
            print('ERROR: plain text should be a 16-digit hexadecimal number.')
            return
        permuted = self.__permute(plain_bin, self.IP)
        tmp = self.__Feistel_encrypt(permuted, r=16)
        cipher = self.__permute(tmp, self.IP_inv)

        return cipher

    
    def __load_array(self, path):
        return np.array(pd.read_csv(path, header=None, dtype=int).values).reshape(-1)
    
    def __hex_to_bin(self, hex):
        return np.array([list(bin(int(c, 16))[2:].zfill(4)) for c in hex], dtype=int).reshape(-1,)
    
    def __permute(self, text, indices):
        return text[indices - 1]

    def __Feistel_encrypt(self, text, r):
        length = text.shape[0]
        L = np.zeros((r, length // 2), dtype=int)
        R = np.zeros((r, length // 2), dtype=int)

        L[0] = text[:length // 2]
        R[0] = text[length // 2:]

        C = np.zeros((r, 28), dtype=int)
        D = np.zeros((r, 28), dtype=int)
        round_keys = np.zeros((r, 48), dtype=int)
        C[0], D[0] = self.__get_initial_CD()
        for i in range(1, r):
            C[i], D[i] = self.__update_CD(C[i-1], D[i-1], i)
            round_keys[i] = self.__permute(np.concatenate((C[i], D[i])), self.PC2)
            L[i], R[i] = self.__iterative_encrypt(L[i-1], R[i-1], round_keys[i])
        
        return np.concatenate((R[r-1], L[r-1]))
    
    # def __Feistel_decrypt(self, text, r, values):

    def __iterative_encrypt(self, L, R, round_key):
        next_L = R
        next_R = L ^ self.__internal_block_encrypt(R, round_key)

        return next_L, next_R
    
    def __internal_block_encrypt(self, R, round_key):
        expanded = self.__permute(R, self.E)
        B = expanded ^ round_key
        B = B.reshape(8, -1)
        C = self.__S_boxes(B)
        C = C.reshape(-1,)
        retval = self.__permute(C, self.P)

        return retval

    # def __iterative_decrypt(self, L, R):

    def __S_boxes(self, B):
        C = np.zeros((8, 4), dtype=int)
        for i in range(8):
            C[i] = self.__S_box(i, B[i])
        
        return C

    def __S_box(self, i, B_i):
        row = B_i[0] * 2 + B_i[5]
        col = B_i[1] * 8 + B_i[2] * 4 + B_i[3] * 2 + B_i[4]

        value = self.S[i][row][col]

        retval = np.zeros(4)
        for i in range(4):
            retval[3-i] = value % 2
            value = value // 2
        
        return retval
    
    def __get_initial_CD(self):
        CD = self.__permute(self.des_key_bin, self.PC1)
        length = CD.shape[0]
        C = CD[:length // 2]
        D = CD[length // 2:]

        return C, D
    
    def __update_CD(self, C, D, i):
        value = self.values[i]
        next_C = np.roll(C, -value)
        next_D = np.roll(D, -value)

        return next_C, next_D


# In[2]:


des = DES(key='133457799BBCDFF1')

cipher = des.encrypt('0123456789ABCDEF')


# In[ ]:


if 'get_ipython' in globals():
    import subprocess
    subprocess.run(['jupyter', 'nbconvert', '--to', 'python', '*.ipynb'])
    print('Saved as auto_encoder.py')

