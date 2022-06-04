from Crypto.Cipher import AES
from secrets import token_bytes

key = token_bytes(16)
# 128 bytes of AES
# define an enquiption function 
def encryption_function(msg):
    # retuns nonce, ciphertext, tag
    # contruct the cypher object with parameters key and mode of operation
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    # take masage as bytes 
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag

def decryption_fuction(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False

nonce, ciphertext, tag = encryption_function(input('Please Enter the  message to encrpt: '))
plaintext = decryption_fuction(nonce, ciphertext, tag)
print(f'My Cipher text message is : {ciphertext}')


if  plaintext:
    print(f'My Plain text message is : {plaintext}')
else:
    print('Message is corrupted or Null')

    