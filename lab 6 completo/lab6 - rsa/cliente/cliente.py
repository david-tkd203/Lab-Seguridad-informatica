import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def cargar_clave_publica(pub_key):
    return serialization.load_pem_public_key(pub_key)

def cifrar_mensaje(public_key, mensaje):
    cifrado = public_key.encrypt(
        mensaje.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cifrado

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 12345))

    # Recibir clave pública del servidor
    public_key_bytes = client_socket.recv(4096)
    public_key = cargar_clave_publica(public_key_bytes)

    # Leer mensaje desde el archivo
    with open("mensajeentrada.txt", "r") as file:
        mensaje = file.read()

    # Cifrar y enviar el mensaje al servidor
    mensaje_cifrado = cifrar_mensaje(public_key, mensaje)
    client_socket.send(mensaje_cifrado)

    client_socket.close()

if __name__ == "__main__":
    main()

