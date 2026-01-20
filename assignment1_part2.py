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
    # Craft input with placeholders we will flip: '?admin?true?'
    # We'll flip the three '?' to ';', '=' and ';' to inject ';admin=true;'
    user_input = "?admin?true?"
    ciphertext = submit(user_input)
    message = f"userid=456;userdata={urlEncode(user_input)};session-id=31337".encode("ascii")

    flips = []
    # Locate the three '?' placeholders in the message
    question_positions = [m.start() for m in re.finditer(br'\?', message)]
    if len(question_positions) < 3:
        raise ValueError("Expected at least three '?' placeholders in the message")

    # Map each placeholder to desired target byte
    targets = [';', '=', ';']
    cipher_flipped = bytearray(ciphertext)
    for pos, target in zip(question_positions[:3], targets):
        block_num = pos // 16
        if block_num == 0:
            raise ValueError("Placeholder fell in block 0; choose a different input")
        offset = pos % 16
        prev_block_start = (block_num - 1) * 16
        flip_idx = prev_block_start + offset
        original_byte = message[pos]
        cipher_flipped[flip_idx] ^= (original_byte ^ ord(target))
        flips.append((pos, flip_idx, chr(original_byte), target))

    # decrypt both 
    cipher = AES.new(key, AES.MODE_CBC, iv)
    before_flip = unpad(cipher.decrypt(ciphertext), 16, style="pkcs7")
    after_flip = unpad(cipher.decrypt(bytes(cipher_flipped)), 16, style="pkcs7")
    print("Before flip:", before_flip)
    print("After flip:", after_flip)
    for pos, flip_idx, orig, target in flips:
        print(f"Changed byte: plaintext offset {pos}, ciphertext index {flip_idx}, '{orig}' -> '{target}'")

    print("verify(original) ->", verify(ciphertext))
    print("verify(modified) ->", verify(bytes(cipher_flipped))) 

key = get_random_bytes(16)
iv = get_random_bytes(16)

bitFlip()