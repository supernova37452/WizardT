import os
import base64
from flask import Flask, request, render_template, send_file
from html import escape
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#this is just to configure all the file paths and so that the .py will need (the htmls and the css)
app = Flask(__name__, template_folder='.', static_folder='.', static_url_path='')

#key and val
FLAG = os.getenv("FLAG", "flame{TheWizardOfCrypto}")

#key_hex asa 64char hex string or 32 bytes so the key itself is more stable for the contestants
key_hex = os.getenv("APP_KEY_HEX")
if key_hex:
    try:
        KEY = bytes.fromhex(key_hex)
        if len(KEY) not in (16, 24, 32):
            raise ValueError("APP_KEY_HEX must decode to 16, 24, or 32 bytes.")
    except Exception as e:
        raise SystemExit(f"Invalid APP_KEY_HEX: {e}")
else:
    # no key? i do give one but this is just in case: generate a 16byte key
    KEY = os.urandom(16)

#AES-Ctr with a fixed nonce so thetokens r forgeable lol, if they keep changing itll be hard to forge it unless we use additional key/auth
NONCE = b"\x00" * 16 #make them the same fitst bytes

#AES-CTr encrypt -takes plaintext bytes, XORs with keystream, returns ciphertext
def aes_ctr_encrypt(pt: bytes) -> bytes:
    enc = Cipher(algorithms.AES(KEY), modes.CTR(NONCE)).encryptor()
    return enc.update(pt) + enc.finalize()

#AES-CTr decrypt -reverses encrypt (same keystream), returns plaintext bytes
def aes_ctr_decrypt(ct: bytes) -> bytes:
    dec = Cipher(algorithms.AES(KEY), modes.CTR(NONCE)).decryptor()
    return dec.update(ct) + dec.finalize()

#all of my routes
@app.route("/styles.css")
def styles():
    return send_file(os.path.join(os.path.dirname(__file__), "styles.css"), mimetype="text/css")

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/get_token")
def get_token():
    pt = b"username=guests|role=user"
    ct = aes_ctr_encrypt(pt)
    token = base64.b64encode(NONCE + ct).decode()
    return render_template("get_token.html", token=escape(token))

@app.route("/use_token", methods=["GET", "POST"])
def use_token():
    if request.method == "GET":
        return render_template("use_token.html")

    token = (request.form.get("token") or "").strip()
    if not token:
        return render_template("use_token.html", msg="No token provided, apprentice.")

    #docoding base64 with padding
    try:
        pad = (-len(token)) % 4
        token_p = token + ("=" * pad)
        data = base64.b64decode(token_p)
    except Exception:
        return render_template("use_token.html", msg="The spell fizzled... invalid token format.")

    try:
        if len(data) < 16:
            raise ValueError("too short")
        ct = data[16:]
        pt = aes_ctr_decrypt(ct).decode(errors="ignore")
    except Exception:
        return render_template("use_token.html", msg="The spell fizzled... invalid token.")

    #this is to make sure the flag is only revealed if it follows the exact admin role text
    if "|role=admin" in pt:
        return render_template("use_token.html", flag=FLAG)

    #generic noadmin message (do not show plaintext...)
    return render_template("use_token.html", pt=escape(pt))

if __name__ == "__main__":
    app.run(port=5001)
