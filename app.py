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
import time

app = Flask(__name__)
app.logger.setLevel(logging.INFO)


# ---------------- TOKEN LOADER ---------------- #
def load_tokens(server_name):
    try:
        if server_name == "IND":
            filename = "token_id.json"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            filename = "token_br.json"
        else:
            filename = "token_bd.json"  # untuk BD region

        with open(filename, "r") as f:
            tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None


# ---------------- ENCRYPTION ---------------- #
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


# ---------------- PROTOBUF CREATION ---------------- #
def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region.upper()  # penting: huruf besar
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None


# ---------------- ASYNC REQUEST ---------------- #
async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                app.logger.info(f"Like sent -> token: {token[:10]}... | status: {response.status}")
                return response.status
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None


# ---------------- MULTI REQUEST ---------------- #
async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            return None
        tasks = []
        tokens = load_tokens(server_name)
        if not tokens:
            return None
        for i in range(100):
            token = tokens[i % len(tokens)].get("token")
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None


# ---------------- UID ENCRYPT ---------------- #
def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None


def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid


# ---------------- DECODE PROTOBUF ---------------- #
def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError:
        return None


# ---------------- MAKE REQUEST ---------------- #
def make_request(encrypt_hex, server_name, token):
    try:
        if server_name == "bd":
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        elif server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"

        edata = bytes.fromhex(encrypt_hex)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        response = requests.post(url, data=edata, headers=headers, timeout=15)
        decode = decode_protobuf(response.content)
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None


# ---------------- FETCH PLAYER INFO ---------------- #
def fetch_player_info(uid):
    try:
        url = f"https://infoapi-76742.vercel.app/info?server-name=bd&uid={uid}"
        response = requests.get(url, timeout=8)
        if response.status_code == 200:
            data = response.json()
            return {
                "Level": data.get("level", "NA"),
                "Region": "BD",
                "ReleaseVersion": data.get("release_version", "OB50")
            }
        return {"Level": "NA", "Region": "BD", "ReleaseVersion": "OB50"}
    except Exception:
        return {"Level": "NA", "Region": "BD", "ReleaseVersion": "OB50"}


# ---------------- MAIN LIKE ENDPOINT ---------------- #
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "UID is required"}), 400

    server_name_used = "bd"  # locked ke BD region

    try:
        player_info = fetch_player_info(uid)
        region = player_info["Region"]
        level = player_info["Level"]
        release_version = player_info["ReleaseVersion"]

        tokens = load_tokens(server_name_used)
        if not tokens:
            raise Exception("Failed to load tokens.")
        token = tokens[0].get('token')

        encrypted_uid = enc(uid)
        if not encrypted_uid:
            raise Exception("Encryption failed.")

        before = make_request(encrypted_uid, server_name_used, token)
        if before is None:
            raise Exception("Failed to retrieve player info before like.")

        jsone = MessageToJson(before)
        data_before = json.loads(jsone)
        before_like = int(data_before.get('AccountInfo', {}).get('Likes', 0))

        # URL server BD
        url = "https://clientbp.ggblueshark.com/LikeProfile"

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_multiple_requests(uid, server_name_used, url))
        loop.close()

        # 💤 Delay biar server sempat update
        time.sleep(5)

        after = make_request(encrypted_uid, server_name_used, token)
        if after is None:
            raise Exception("Failed to retrieve player info after like.")
        jsone_after = MessageToJson(after)
        data_after = json.loads(jsone_after)
        after_like = int(data_after.get('AccountInfo', {}).get('Likes', before_like))

        like_given = after_like - before_like
        player_uid = int(data_after.get('AccountInfo', {}).get('UID', uid))
        player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', 'Unknown'))

        result = {
            "UID": player_uid,
            "PlayerNickname": player_name,
            "Region": region,
            "Level": level,
            "LikesBefore": before_like,
            "LikesAfter": after_like,
            "LikesGivenByAPI": like_given,
            "ReleaseVersion": release_version,
            "status": 1 if like_given > 0 else 2
        }
        return jsonify(result)

    except Exception as e:
        app.logger.error(f"Error processing request: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500