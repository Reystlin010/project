import base64
import hashlib
import hmac
import binascii
import json
from typing import Optional
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response


app = FastAPI()

PASSWORD_SALT = "6191e0989369cbebaff1e3e6462c97325ca5e12ef19c9ca1f8a1415f94d0dba6"

SECRET_KEY = "f57c9034939ff6cb88c9d4a0ec37bc17df7cfb1ad7be497191f848b4b36e1c1e"

def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower() 
    return stored_password_hash == password_hash

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    if "." not in username_signed:
        return None
    username_base64, sign = username_signed.split(".")
    try:
        username = base64.b64decode(username_base64.encode(), validate=True).decode()
    except binascii.Error:
        return None
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username
    else:
        return None

users = {
    "reyst@mail.ru": {
        "name": "Рейст",
        "password": "633594225c2326c816ddf9a1ea47992134f78c7f7c121a2b08ab7a116aafdce5",
        "karma": "1"
    },
    "marksman@rambler.ru": {
        "name": "Марк",
        "password": "9990455eec2d7f01cf261558d25c01a41c246dd551890df89409251c9336096e",
        "karma": 2
    }
}

@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open ("templates/login.html", "r") as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}!<br />"
        f"Ваша карма: {users[valid_username]['karma']}",
        media_type="text/html")

@app.post("/login")
def process_login_page(username : str = Form(...), password : str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю"
            }),
            media_type="application/json")
    response = Response(
        json.dumps({
            "success": True,
            "message": f"Дарова, {user['name']}!<br />Твоя карма: {user['karma']}"
        }),
        media_type="application/json")

    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response
