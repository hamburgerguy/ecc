from flask import Flask, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii
from flask_app import db


app = Flask(__name__)
app.config["DEBUG"] = True

SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="acorbo93",
    password="daddy222",
    hostname="acorbo93.mysql.pythonanywhere-services.com",
    databasename="acorbo93$comments",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class Comment(db.Model):

    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(4096))

db.create_all()

comments = []
data = []

def crand(seed):
    r = []
    r.append(seed)
    for i in range(30):
        r.append((16807*r[-1])%2147483647)
        if r[-1] < 0:
            r[-1] += 2147483647
    for i in range(31,34):
        r.append(r[len(r)-31])
    for i in range(34,344):
        r.append((r[len(r)-31]+r[len(r)-3])%2**32)
    while True:
        next = r[len(r)-31]+r[len(r)-3]%2**32
        r.append(next)
        yield (next >> 1 if next < 2**32 else (next % 2**32) >> 1)

mygen = crand(2018)
rands = [next(mygen) for i in range(4)]


def xencrypt(plaintext,rands):
    hexplain = binascii.hexlify(plaintext)
    hexkey = "".join(map(lambda x: format(x, 'x')[-6:], rands))
    cipher_as_int = int(hexplain,16)^int(hexkey,16)
    cipher_as_hex = format(cipher_as_int,'x')
    return cipher_as_hex

def xdecrypt(ciphertext,rands):
    hexkey = "".join(map(lambda x: format(x, 'x')[-6:], rands))
    cipher_as_int = int(ciphertext, 16)^ int(hexkey,16)
    return binascii.unhexlify(format(cipher_as_int,'x'))


def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32,'big'))
    sha.update(int.to_bytes(point.x,32,'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')

def encrypt_ECC(msg, pubkey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubkey
    secretkey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg,secretkey)
    ciphertextPubKey = ciphertextPrivKey* curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey*ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext,nonce,authTag,secretKey)
    return plaintext



privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

data = []

@app.route("/", methods=["GET", "POST"])
def index():

    if request.method == "GET":
        return render_template("main_page.html", comments=comments)
    index = 0
    for i in data:
        index += 1
    if request.form["action"] == "Encrypt":
        data.append(encrypt_ECC(bytes(request.form["contents"],'utf-8'),pubKey))
        comments.append(bytearray(data[index][0]).hex())
    elif request.form["action"] == "Decrypt":
        comments.append(str(decrypt_ECC(data[index-1],privKey))[1:])

    return redirect(url_for('index'))
