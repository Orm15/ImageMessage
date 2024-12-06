from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
import os
import base64
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image
import time

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "outputs"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def limpiar_uploads(minutos_limite=10):
    limite_segundos = minutos_limite * 60
    # Función auxiliar para eliminar archivos antiguos en una carpeta
    def eliminar_archivos_carpeta(carpeta):
        try:
            tiempo_actual = time.time()
            for entry in os.scandir(carpeta):
                if entry.is_file():
                    tiempo_modificacion = entry.stat().st_mtime
                    # Si el archivo es más antiguo que el límite especificado, lo eliminamos
                    if tiempo_actual - tiempo_modificacion > limite_segundos:
                        os.remove(entry.path)
                        print(f"Archivo eliminado: {entry.name}")
        except Exception as e:
            print(f"Error al limpiar la carpeta {carpeta}: {str(e)}")

    # Limpiar tanto la carpeta de uploads como la de outputs
    eliminar_archivos_carpeta(UPLOAD_FOLDER)
    eliminar_archivos_carpeta(OUTPUT_FOLDER)


# Función para encriptar el mensaje
def encrypt_message(message, password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding del mensaje
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    encrypted_message = iv + encryptor.update(padded_message) + encryptor.finalize()
    return base64.b64encode(encrypted_message).decode()

# Función para ocultar el mensaje en la imagen
def hide_message_in_image(image_path, output_path, message):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())

    binary_message = ''.join(format(ord(char), '08b') for char in message) + '1111111111111110'
    message_index = 0

    new_pixels = []
    for pixel in pixels:
        if message_index < len(binary_message):
            r, g, b = pixel
            r = (r & ~1) | int(binary_message[message_index])
            message_index += 1
            if message_index < len(binary_message):
                g = (g & ~1) | int(binary_message[message_index])
                message_index += 1
            if message_index < len(binary_message):
                b = (b & ~1) | int(binary_message[message_index])
                message_index += 1
            new_pixels.append((r, g, b))
        else:
            new_pixels.append(pixel)

    img.putdata(new_pixels)
    img.save(output_path)

@app.route("/")
def index():
    return render_template("home.html")

@app.route("/set")
def index1():
    return render_template("getMessage.html")

@app.route("/get")
def index2():
    return render_template("setMessage.html")

@app.route("/process", methods=["POST"])
def process():
    try:
        image = request.files["image"]
        message = request.form["message"]
        password = request.form["password"]

        if not image or not message or not password:
            return jsonify({"success": False, "error": "Todos los campos son obligatorios"})


        ## Eliminar imagenes: 
        limpiar_uploads()
        filename = secure_filename(image.filename)
        image_path = os.path.join(UPLOAD_FOLDER, filename)
        image.save(image_path)

        salt = os.urandom(16)
        encrypted_message = encrypt_message(message, password, salt)

        output_filename = f"output_{filename}"
        output_path = os.path.join(OUTPUT_FOLDER, output_filename)
        hide_message_in_image(image_path, output_path, encrypted_message)

        # Retornar el nombre del archivo procesado junto con la contraseña y el salt
        return jsonify({
            "success": True,
            "password": password,
            "salt": base64.b64encode(salt).decode(),
            "image_url": f"/download/{output_filename}"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/download/<filename>")
def download(filename):
    output_path = os.path.join(OUTPUT_FOLDER, filename)
    if not os.path.exists(output_path):
        return "Archivo no encontrado", 404
    return send_file(output_path, as_attachment=True)

@app.route("/decrypt", methods=["POST"])
def decrypt():
    try:
        image = request.files["image"]
        password = request.form["password"]
        salt = request.form["salt"]

        if not image or not password or not salt:
            return jsonify({"success": False, "error": "Todos los campos son obligatorios"})

        salt = base64.b64decode(salt)
        image_path = os.path.join(UPLOAD_FOLDER, secure_filename(image.filename))
        image.save(image_path)

        # Extraer el mensaje oculto de la imagen
        hidden_message = extract_message_from_image(image_path)

        # Desencriptar el mensaje
        decrypted_message = decrypt_message(hidden_message, password, salt)

        return jsonify({"success": True, "message": decrypted_message})
    except Exception as e:
        print(e)
        return jsonify({"success": False, "error": str(e)})

def extract_message_from_image(image_path):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())

    binary_message = ""
    for pixel in pixels:
        r, g, b = pixel
        binary_message += str(r & 1)  # LSB de R
        binary_message += str(g & 1)  # LSB de G
        binary_message += str(b & 1)  # LSB de B

    # Buscar el marcador de fin ('1111111111111110')
    end_marker = "1111111111111110"
    end_index = binary_message.find(end_marker)
    if end_index == -1:
        raise ValueError("No se encontró un mensaje válido en la imagen.")

    # Convertir los bits a texto
    binary_message = binary_message[:end_index]
    chars = [chr(int(binary_message[i:i + 8], 2)) for i in range(0, len(binary_message), 8)]
    return ''.join(chars)

def decrypt_message(encrypted_message, password, salt):
    # Desencriptar el mensaje
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Desencriptar y eliminar el padding
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()


if __name__ == "__main__":
    #app.run(debug=True)
    port = int(os.environ.get("PORT", 5000))
    # Ejecuta en 0.0.0.0 para que Render pueda acceder
    app.run(host="0.0.0.0", port=port)
