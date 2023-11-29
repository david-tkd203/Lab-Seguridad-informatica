import socket
import json
import random

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keypair(p):
    # Genera las claves pública y privada para ElGamal
    g = 2  # Raíz primitiva módulo p

    x = random.randint(2, p - 2)  # Clave privada
    h = pow(g, x, p)  # Clave pública

    return p, g, h, x

def elgamal_encrypt(message, p, g, h):
    k = random.randint(2, p - 2)  # Clave efímera

    c1 = pow(g, k, p)
    s = pow(h, k, p)
    c2 = (message * s) % p

    return c1, c2

def elgamal_decrypt(ciphertext, p, x):
    c1, c2 = ciphertext
    s = pow(c1, x, p)
    plaintext = (c2 * mod_inverse(s, p)) % p
    return plaintext

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(1)

    print("Esperando conexiones...")
    client_socket, addr = server_socket.accept()
    print("Conexión establecida desde", addr)

    # Genera las claves para ElGamal
    p, g, h, x = generate_keypair(9833)

    # Envía la clave pública al cliente
    client_socket.send(str(h).encode())

    # Recibe el cifrado del cliente
    ciphertext_str = client_socket.recv(1024).decode()
    ciphertext_json = json.loads(ciphertext_str)

    # Descifra el mensaje
    decrypted_message = [elgamal_decrypt(tuple(c), p, x) for c in ciphertext_json]

    # Convierte los números descifrados a caracteres y concatena el mensaje
    decrypted_str = ''.join([chr(num) for num in decrypted_message])

    # Guarda el mensaje descifrado en un archivo
    with open("mensajerecibido.txt", "w") as f:
        f.write(decrypted_str)

    print("Mensaje descifrado guardado en mensajerecibido.txt")

    client_socket.close()

if __name__ == "__main__":
    start_server()
