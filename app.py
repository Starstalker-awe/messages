from flask import Flask, render_template as render, request, session, redirect, url_for as url
from datetime import timedelta, datetime
import flask_socketio as socketio
from werkzeug.security import generate_password_hash as generate, check_password_hash as check
from dotmap import DotMap
from functools import wraps
import flask_session
from threading import Thread
from tempfile import mkdtemp as tempdir
from requests import get as requestUrl
import json
from uuid import uuid4
from cs50 import SQL
import re
from copy import deepcopy

app = Flask(__name__)

app.config.update({
  "TEMPLATES_AUTO_RELOAD": True,
  "SESSION_FILE_DIR": tempdir(),
  "SESSION_TYPE": "filesystem",
  "SESSION_PERMANENT": True,
  "PERMANENT_SESSION_LIFETIME": timedelta(days=7),
  "SECRET_KEY": uuid4().hex
})

flask_session.Session(app)
socket_ = socketio.SocketIO(app, async_mode="eventlet", manage_session=False)
DB, EXPLOITS = SQL("sqlite:///db/data.db"), SQL("sqlite:///db/exploits.db")

user_map = {u_id: None for u_id in map(lambda u:u['u_id'], DB.execute("SELECT * FROM users WHERE active = 1"))}
PASS_CACHE, CONNECTED = deepcopy(user_map) * 2
EMAIL_RE = re.compile(r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+")

def login_required(f: function): # Wrapper for routes
  @wraps(f)
  def deced(*args: list, **kwargs: object):
    if (uid := session.get("u_id")) and next(iter(DB.execute("SELECT p_id FROM users WHERE u_id = ?", uid)), {}).get("p_id") == session.get("p_id"):
      return f(*args, **kwargs)
    return redirect(url("login"), next = request.path)
  return deced

def log_exploit(exploit: str, ip: str) -> None:
  EXPLOITS.execute("INSERT INTO exploits (id, ip, exploit) VALUES (:id, :ip, :exploit)", id = (id := uuid4().hex), ip = ip, exploit = exploit)
  def query_chance(id: str, qip: str) -> object:
    query = DotMap(requestUrl(
      url = "https://check.getipintel.net/check.php", 
      params = {
        'ip': qip,
        'contact': 'travelingtrevor123@gmail.com',
        'flags': 'f',
        'format': 'json'
      }
    ).json())
    return EXPLOITS.execute("UPDATE exploits SET vpn_chance = :chance WHERE id = :id", id = id, chance = query.result if query.result > -0.01 else None)
  Thread(target=query_chance, args=(id, ip,)).start()

@app.route("/login", methods = ["GET", "POST"])
def login():
  if request.method == 'POST':
    form = DotMap(json.loads(request.data))
    username = form.username.lower() if re.fullmatch(EMAIL_RE, form.username.lower()) else form.username
    if (user := DotMap(next(iter(DB.execute("SELECT * FROM users WHERE username = :un OR lower(email) = :un", un = username)), {}))).get("u_id"):
      if PASS_CACHE[user.u_id] and PASS_CACHE[user.u_id] == form.password or check(form.password, user.phash):
        session.update({"u_id": user.u_id, "p_id": user.p_id, "loggedin": datetime.utcnow(), "username": user.username})
        PASS_CACHE[user.u_id] = form.password
        return {"data": {"error": False, "u_id": user.u_id}}
    return {"data": {"error": True}}
  return render("user/login.html")