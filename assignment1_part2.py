from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad #just to check the result decryption
import re

def pad(message):
    padding_length = 16 - (len(message) % 16) #how much is left until 16 
    padding = bytes([padding_length] * padding_length)
    return message + padding

#helper function to xor individual bytes in the cipher text strings since xor is bitwise operator
def xor_bytes(a, b):
    return bytes([a[i] ^ b[i] for i in range(16)])

def urlEncode(s):
    return s.replace(";", "%3B").replace("=", "%3D")

def submit(user_input):
    url_encoded_input = urlEncode(user_input)
    message = f"userid=456;userdata={url_encoded_input};session-id=31337"
    return CBC_encrypt(message.encode("ascii")) #have to convert back to ascii

def verify(ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    plaintext = unpad(padded, 16, style="pkcs7")
    if (b";admin=true;" in plaintext):
        return True
    return False

def CBC_encrypt(plaintext):
    CBC_output = bytearray()
    cipher = AES.new(key, AES.MODE_ECB) 
    padded_message = pad(plaintext) #starting point
    prev_message = xor_bytes(padded_message[:16], iv)
    prev_message_enc = cipher.encrypt(prev_message)
    CBC_output += prev_message_enc
    for i in range(16, len(padded_message), 16):
        ciphertext = cipher.encrypt(xor_bytes(padded_message[i:i+16], prev_message_enc))
        prev_message_enc = ciphertext
        CBC_output += prev_message_enc
    return bytes(CBC_output)

def bitFlip():
    user_input = ":admin/true"
    ciphertext = submit(user_input)
    message = f"userid=456;userdata={urlEncode(user_input)};session-id=31337".encode("ascii")
    # Find position of '/', and ':''s for bit flipping
    slash_pos = message.index(b'/')#b'/' is bytes
    colon_pos = message.index(b':')#another safe char 

    #flipping the '/' to '='
    block_num = slash_pos // 16
    offset = slash_pos % 16
    prev_block_start = (block_num-1) * 16
    flip_idx1 = prev_block_start + offset
    cipherFlipped = bytearray(ciphertext)
    cipherFlipped[flip_idx1] ^= (ord("/") ^ ord("="))

    #flipping the ':' to ';'
    block_num = colon_pos // 16
    offset = colon_pos % 16
    prev_block_start = (block_num-1) * 16
    flip_idx2 = prev_block_start + offset
    cipherFlipped[flip_idx2] ^= (ord(":") ^ ord(";"))


    #decrypt both 
    cipher = AES.new(key, AES.MODE_CBC, iv)
    beforeFlip = unpad(cipher.decrypt(ciphertext), 16, style="pkcs7")
    afterFlip = unpad(cipher.decrypt(bytes(cipherFlipped)), 16, style="pkcs7")

    # show ciphertext before flip
    print("\nBefore :admin/true - Ciphertext (hex):")
    ciphertext_hex = ''.join([hex(x)[2:].zfill(2) for x in ciphertext])
    print(ciphertext_hex)
    print("\nAfter ;admin=true; - Ciphertext (hex):")
    modified_hex = ''.join([hex(x)[2:].zfill(2) for x in cipherFlipped])
    print(modified_hex)

    # Show the changed byte
    print(f"Original bytes: {hex(ciphertext[flip_idx1])[2:].zfill(2)}, {hex(ciphertext[flip_idx2])[2:].zfill(2)}")
    print(f"Modified bytes: {hex(cipherFlipped[flip_idx1])[2:].zfill(2)}, {hex(cipherFlipped[flip_idx2])[2:].zfill(2)}")
    print("Changed byte indices in ciphertext: ",flip_idx1,",",flip_idx2)

    print("Plaintext before flip:", beforeFlip)
    print("Plaintext after flip:", afterFlip)


    print("verify(original) ->", verify(ciphertext))
    print("verify(modified) ->", verify(bytes(cipherFlipped))) 



key = get_random_bytes(16)
iv = get_random_bytes(16)

bitFlip()
   
