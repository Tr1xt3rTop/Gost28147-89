def text_to_bits(text, encoding='Windows-1251', errors='surrogatepass'):
    bits = bin(int.from_bytes(text.encode(encoding, errors), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

def text_from_bits(bits, encoding='Windows-1251', errors='surrogatepass'):
    n = int(bits, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode(encoding, errors) or '\0'

def round_key_decrypt(key,round):
    if round < 8:
        return key[(round % 8) * 4:(round % 8) * 4 + 4]
    else:
        return (key[(32 - ((round % 8) * 4)) - 4:32 - ((round % 8) * 4)])

def round_key(key,round):
    if round < 24:
        return key[(round%8)*4:(round%8)*4+4]
    else:
        return (key[(32-((round%8)*4))-4:32-((round%8)*4)])

def f(key,round,R):
    return ((int(text_to_bits(round_key(key,round)),2)+int(R,2)) % (2**32))

def f_decrypt(key,round,R):
    return ((int(text_to_bits(round_key_decrypt(key, round)), 2) + int(R, 2)) % (2 ** 32))

def Permutation_Sblock(key,R,round):
    fblock = bin(f(key,round,R))[2:].zfill(32)
    R = ""
    for i in range(int(len(fblock)/4)):
        R += bin(Sblock[i][int(fblock[i*4:i*4+4],2)])[2:].zfill(4)
    return (R[11:len(R)]+R[0:11])

def Permutation_Sblock_decrypt(key,R,round):
    fblock = bin(f_decrypt(key,round,R))[2:].zfill(32)
    R = ""
    for i in range(int(len(fblock)/4)):
        R += bin(Sblock[i][int(fblock[i*4:i*4+4],2)])[2:].zfill(4)

    return (R[11:len(R)]+R[0:11])

def encryption(key,R,L):
    Rnew = ""
    for round in range(32):
        fblock = Permutation_Sblock(key,R,round)
        Rnew = bin(int(fblock,2)^int(L,2))[2:].zfill(32)
        L = R
        R = Rnew

    return text_from_bits(L+R)

def decrypt(key,R,L):
    Rnew = ""
    for round in range(32):
        fblock = Permutation_Sblock_decrypt(key,R,round)
        Rnew = bin(int(fblock,2)^int(L,2))[2:].zfill(32)
        L = R
        R = Rnew

    return text_from_bits(R+L)

Sblock = [
    [1,15,13,0,5,7,10,4,9,2,3,14,6,11,8,12],
    [13,11,4,1,3,15,5,9,0,10,14,7,6,8,2,12],
    [4,11,10,0,7,2,1,13,3,6,8,5,9,12,15,14],
    [6,12,7,1,5,15,13,8,4,10,9,14,0,3,11,2],
    [7,13,10,1,0,8,9,15,14,4,6,12,11,2,5,3],
    [5,8,1,13,10,3,4,2,14,15,12,7,6,0,9,11],
    [14,11,4,12,6,13,15,10,2,3,8,1,0,7,5,9],
    [4,10,9,2,13,8,0,14,6,11,1,12,7,15,5,3]
]

data = "Hellowor"
key = "алина пошла в лес собирать грибы"

L = text_to_bits(data)[:32]
R = text_to_bits(data)[32:]

encriptiondata = encryption(key,R,L)

R1 = text_to_bits(encriptiondata)[:32]
L1 = text_to_bits(encriptiondata)[32:]

print(encriptiondata)

decryptdata = decrypt(key,R1,L1)

print(decryptdata)

