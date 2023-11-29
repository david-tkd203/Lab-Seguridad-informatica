import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generar_par_de_claves():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def guardar_clave_privada(priv_key, filename="private_key.pem"):
    with open(filename, "wb") as key_file:
        key_file.write(priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

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

def descifrar_mensaje(private_key, cifrado):
    mensaje = private_key.decrypt(
        cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensaje.decode()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 12345))
    server_socket.listen()

    print("Esperando conexión del cliente...")
    client_socket, addr = server_socket.accept()
    print(f"Conexión establecida desde {addr}")

    private_key, public_key = generar_par_de_claves()

    guardar_clave_privada(private_key)

    # Enviar clave pública al cliente
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(public_key_bytes)

    # Recibir mensaje cifrado del cliente
    mensaje_cifrado = client_socket.recv(4096)

    # Descifrar el mensaje
    mensaje_descifrado = descifrar_mensaje(private_key, mensaje_cifrado)
    print(f"Mensaje descifrado: {mensaje_descifrado}")

    # Guardar el mensaje descifrado en un archivo
    with open("mensajerecibido.txt", "w") as file:
        file.write(mensaje_descifrado)

    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    main()
