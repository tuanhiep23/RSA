import asyncio
import websockets
import hashlib
import base64
import os
import json
from cryptography.hazmat.primitives import serialization

RECEIVE_DIR = "received_files"
os.makedirs(RECEIVE_DIR, exist_ok=True)

# Lưu kết nối WebSocket và public key theo username
connected_clients = dict()  # username:str -> {"websocket": websocket, "public_key": public_key_pem}

async def notify_user_not_found(websocket, target_user):
    await websocket.send(json.dumps({
        "status": "error",
        "message": f"Người nhận '{target_user}' không online hoặc không tồn tại."
    }))

async def handle_login(websocket, message):
    username = message.get("username")
    public_key_b64 = message.get("public_key")
    if not username or not public_key_b64:
        await websocket.send(json.dumps({
            "status": "error",
            "message": "Bạn cần nhập username và public key để đăng nhập."
        }))
        return False

    if username in connected_clients:
        await websocket.send(json.dumps({
            "status": "error",
            "message": f"Username '{username}' đã được sử dụng."
        }))
        return False

    try:
        public_key_pem = base64.b64decode(public_key_b64).decode('utf-8')
        connected_clients[username] = {
            "websocket": websocket,
            "public_key": public_key_pem
        }
        await websocket.send(json.dumps({
            "status": "success",
            "message": f"Đăng nhập thành công với username '{username}'."
        }))
        print(f"{username} đã đăng nhập.")
        return True
    except Exception as e:
        await websocket.send(json.dumps({
            "status": "error",
            "message": f"Lỗi xử lý public key: {str(e)}"
        }))
        return False

async def handle_logout(websocket):
    to_remove = None
    for user, info in connected_clients.items():
        if info["websocket"] == websocket:
            to_remove = user
            break
    if to_remove:
        del connected_clients[to_remove]
        print(f"{to_remove} đã đăng xuất.")

async def handle_send_file(websocket, message):
    sender = message.get("sender")
    receiver = message.get("receiver")
    filename = message.get("filename")
    filedata_b64 = message.get("filedata")
    checksum_client = message.get("checksum")
    signature_b64 = message.get("signature")  # Thêm chữ ký số

    if not sender or not receiver or not filename or not filedata_b64 or not checksum_client or not signature_b64:
        await websocket.send(json.dumps({
            "status": "error",
            "message": "Dữ liệu gửi file không đầy đủ."
        }))
        return

    if receiver not in connected_clients:
        await notify_user_not_found(websocket, receiver)
        return

    try:
        filedata = base64.b64decode(filedata_b64)
        sha256 = hashlib.sha256()
        sha256.update(filedata)
        checksum_server = sha256.hexdigest()

        if checksum_server != checksum_client:
            await websocket.send(json.dumps({
                "status": "error",
                "message": "Kiểm tra checksum không khớp. File bị hỏng."
            }))
            return
    except Exception as e:
        await websocket.send(json.dumps({
            "status": "error",
            "message": f"Không thể giải mã filedata: {str(e)}"
        }))
        return

    filepath = os.path.join(RECEIVE_DIR, f"{sender}_to_{receiver}_" + filename)
    with open(filepath, 'wb') as f:
        f.write(filedata)

    sender_public_key = connected_clients[sender]["public_key"]
    message_to_receiver = {
        "status": "success",
        "command": "receive_file",
        "sender": sender,
        "filename": filename,
        "filedata": filedata_b64,
        "checksum": checksum_client,
        "signature": signature_b64,  # Chuyển tiếp chữ ký
        "sender_public_key": sender_public_key,
        "message": f"Bạn vừa nhận file '{filename}' từ '{sender}'."
    }

    try:
        await connected_clients[receiver]["websocket"].send(json.dumps(message_to_receiver))
    except:
        await websocket.send(json.dumps({
            "status": "error",
            "message": f"Không gửi được file đến '{receiver}'."
        }))
        return

    await websocket.send(json.dumps({
        "status": "success",
        "message": f"Đã gửi file '{filename}' đến '{receiver}'."
    }))

async def get_public_key(websocket, message):
    target_user = message.get("target_user")
    if target_user not in connected_clients:
        await notify_user_not_found(websocket, target_user)
        return

    await websocket.send(json.dumps({
        "status": "success",
        "command": "public_key",
        "target_user": target_user,
        "public_key": connected_clients[target_user]["public_key"]
    }))

async def handler(websocket):
    logged_in = False
    username = None
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                command = data.get("command")

                if not logged_in:
                    if command == "login":
                        success = await handle_login(websocket, data)
                        if success:
                            logged_in = True
                            username = data.get("username")
                    else:
                        await websocket.send(json.dumps({
                            "status": "error",
                            "message": "Bạn phải đăng nhập trước (command: login)."
                        }))
                else:
                    if command == "send_file":
                        data['sender'] = username
                        await handle_send_file(websocket, data)
                    elif command == "logout":
                        await handle_logout(websocket)
                        break
                    elif command == "get_public_key":
                        await get_public_key(websocket, data)
                    else:
                        await websocket.send(json.dumps({
                            "status": "error",
                            "message": f"Lệnh không hợp lệ hoặc không được hỗ trợ: {command}"
                        }))
            except json.JSONDecodeError:
                await websocket.send(json.dumps({
                    "status": "error",
                    "message": "Dữ liệu gửi lên không phải JSON"
                }))
    finally:
        if logged_in and username in connected_clients:
            del connected_clients[username]
            print(f"{username} đã ngắt kết nối.")

async def main():
    print("Server WebSocket đang lắng nghe ws://localhost:8765")
    async with websockets.serve(handler, "0.0.0.0", 8765):
        await asyncio.Future()

if __name__=="__main__":
    asyncio.run(main())