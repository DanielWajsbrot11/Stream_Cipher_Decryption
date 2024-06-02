def decrypt_stream(key, cipher):
    # Convert key & cipher from hex to int
    key_int = int(key, 16)
    cipher_int = int(cipher, 16)
    
    # Perform XOR operation
    message_int = key_int ^ cipher_int
    
    # Convert the message back to hex
    message_hex = hex(message_int)[2:]
    
    # Convert hex to bytes
    message_bytes = bytes.fromhex(message_hex)
    
    try:
        # Convert bytes to ASCII text
        ascii_text = message_bytes.decode('ascii')
        print("ASCII text: ", ascii_text)
        return ascii_text
    except UnicodeDecodeError:
        # Handle case where byte stream cannot be decoded to ASCII
        print("Decoded bytes cannot be converted to ASCII text")
        return message_bytes

print("Program started... ")
decrypted_text = decrypt_stream("66396e89c9dbd8cc9874", "32510bfbacfbb9befd54")
print("Decrypted text: ", decrypted_text)
