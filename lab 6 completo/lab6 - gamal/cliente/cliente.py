import socket
import json
import random

def elgamal_encrypt(message, h, p, g):
    k = random.randint(2, p - 2)  # Clave efímera

    c1 = pow(g, k, p)
    s = pow(h, k, p)
    c2 = (message * s) % p

    return c1, c2

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8080))

    # Recibe la clave pública del servidor
    server_public_key = int(client_socket.recv(1024).decode())

    # Lee el mensaje desde el archivo mensajeentrada.txt
    with open("mensajeentrada.txt", "r") as f:
        mensaje_str = f.read()

    # Convierte el mensaje a una lista de números (ASCII)
    mensaje_numeros = [ord(char) for char in mensaje_str]

    # Cifra cada número del mensaje
    p = 9833
    g = 2
    ciphertext = [elgamal_encrypt(numero, server_public_key, p, g) for numero in mensaje_numeros]

    # Envía el cifrado al servidor en formato JSON
    ciphertext_str = json.dumps(ciphertext)
    client_socket.send(ciphertext_str.encode())

    client_socket.close()

if __name__ == "__main__":
    start_client()
