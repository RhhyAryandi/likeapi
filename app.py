from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import logging

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# =====================================================
# TOKEN LOADER
# =====================================================
def load_tokens(server_name):
    try:
        if server_name == "IND":
            filename = "token_id.json"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            filename = "token_br.json"
        else:
            filename = "token_bd.json"

        with open(filename, "r") as f:
            tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

# =====================================================
# AES ENCRYPT
# =====================================================
def encrypt_message(plaintext: bytes):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

# =====================================================
# CREATE LIKE PROTOBUF MESSAGE
# =====================================================
def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

# =====================================================
# SEND LIKE REQUEST (ASYNC)
# =====================================================
async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': "2018.4.11f1",
            'ReleaseVersion': "OB50"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                return await response.text()
    except Exception as e:
        app.logger.error(f"send_request error: {e}")
        return None

# =====================================================
# SEND MULTIPLE REQUESTS
# =====================================================
async def send_multiple_requests(uid, server_name, url):
    region = server_name
    protobuf_message = create_protobuf_message(uid, region)
    if not protobuf_message:
        return None
    encrypted_uid = encrypt_message(protobuf_message)
    if not encrypted_uid:
        return None

    tokens = load_tokens(server_name)
    if not tokens:
        return None

    tasks = [
        send_request(encrypted_uid, tokens[i % len(tokens)]["token"], url)
        for i in range(100)
    ]
    return await asyncio.gather(*tasks, return_exceptions=True)

# =====================================================
# UID ENCODER
# =====================================================
def create_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = int(uid)
    message.garena = 1
    return message.SerializeToString()

def enc(uid):
    protobuf_data = create_protobuf(uid)
    return encrypt_message(protobuf_data)

# =====================================================
# DECODE PROTOBUF (LIKE COUNT)
# =====================================================
def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception:
        return None

# =====================================================
# REQUEST PLAYER INFO FROM GAME
# =====================================================
def make_request(encrypt_hex, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

        edata = bytes.fromhex(encrypt_hex)
        headers = {
            'Authorization': f"Bearer {token}",
            'User-Agent': "Dalvik/2.1.0",
            'Content-Type': "application/x-www-form-urlencoded",
        }

        response = requests.post(url, data=edata, headers=headers, timeout=10)
        binary = response.content
        return decode_protobuf(binary)
    except Exception as e:
        app.logger.error(f"make_request error: {e}")
        return None

# =====================================================
# FETCH PLAYER INFO DARI INFOAPI
# =====================================================
def fetch_player_info(uid):
    try:
        url = f"https://infoapi-76742.vercel.app/info?server-name=bd&uid={uid}"
        response = requests.get(url, timeout=8)
        if response.status_code == 200:
            data = response.json()
            acc = data.get("AccountInfo", {})
            region = acc.get("AccountRegion", "Unknown")
            name = acc.get("AccountName", "Unknown")

            app.logger.info(f"[INFO_API] UID: {uid} | Region: {region} | Player: {name}")

            return {"UID": uid, "Region": region, "PlayerNickname": name}
        else:
            return {"UID": uid, "Region": "Unknown", "PlayerNickname": "Unknown"}
    except Exception as e:
        app.logger.error(f"fetch_player_info error: {e}")
        return {"UID": uid, "Region": "Unknown", "PlayerNickname": "Unknown"}

# =====================================================
# MAIN /LIKE ENDPOINT
# =====================================================
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "UID is required"}), 400

    server_name_used = "bd"
    try:
        player_info = fetch_player_info(uid)
        region = player_info["Region"]
        player_name = player_info["PlayerNickname"]

        tokens = load_tokens(server_name_used)
        if not tokens:
            raise Exception("Failed to load tokens.")
        token = tokens[0].get('token')

        encrypted_uid = enc(uid)
        if not encrypted_uid:
            raise Exception("Encryption of UID failed.")

        url = "https://clientbp.ggblueshark.com/LikeProfile"

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_multiple_requests(uid, server_name_used, url))
        loop.close()

        # hasil akhir hanya menampilkan 3 hal
        result = {
            "UID": uid,
            "Region": region,
            "PlayerNickname": player_name,
            "message": "Like sent successfully!"
        }
        return jsonify(result)

    except Exception as e:
        app.logger.error(f"Error processing request: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500