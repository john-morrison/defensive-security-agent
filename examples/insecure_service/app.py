import hashlib
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect(":memory:")
API_TOKEN = "this-is-a-sample-hard-coded-token"


@app.route("/users")
def users():
    user_id = request.args["id"]
    return db.execute(f"select * from users where id = {user_id}").fetchall()


@app.route("/run")
def run_command():
    command = request.args["command"]
    return subprocess.check_output(command, shell=True).decode("utf-8")


@app.route("/load", methods=["POST"])
def load_payload():
    return pickle.loads(request.data)


def fingerprint(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    app.run(debug=True)

