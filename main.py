from flask import Flask, request, Response, render_template

from managers.authentication_manager import AuthenticationManager, Agent
from managers.database_provider.mongodb_provider import MongoDBProvider
from model.authentication import hash_password

import requests


application = Flask(__name__)

database_provider = MongoDBProvider("personal")

authentication_manager = AuthenticationManager(database_provider)
authentication_manager.drop()

[password_hash, password_salt] = hash_password("root")
authentication_manager.create(Agent(-1, "root", "root@localhost", password_hash, password_salt))


@application.route("/")
def index():
    return render_template("index.html", variables={"authentication_URL": "http://localhost:16384/authenticate"})


@application.route("/users", methods=["GET"])
def users():
    return {"users": authentication_manager.all()}


@application.route("/by_id")
def by_id():
    if "user_id" in request.args:
        user_id = int(request.args["user_id"])

        agent = authentication_manager.by_user_id(user_id)

        if agent is not None:
            return {
                "user_id": agent.user_id,
                "username": agent.username,
                "email": agent.email,
            }
        else:
            return str()


@application.route("/authenticate", methods=["POST"])
def authenticate():
    if "identifier" in request.json and "password" in request.json:
        token = authentication_manager.verify(request.json["identifier"], request.json["password"])
        if token is not None:
            return {"token": token}
        else:
            return Response(status=401)
    else:
        return Response(status=400)


@application.route("/action")
def action():
    response = requests.post("http://localhost:16384/authenticate", json={"identifier": "root", "password": "root"})
    return str(response.status_code)


application.run(port=16_384, debug=True)
