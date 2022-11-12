import jwt
from flask import Flask, request, Response, render_template
from flask_cors import CORS

from configuration.configuration import configuration, authentication_manager, initialize_database, create_root_user

import requests
from dataclasses import asdict

application = Flask(__name__)
CORS(application)

initialize_database()
create_root_user()


@application.route("/")
def index():
    return render_template("index.html", variables=asdict(configuration))


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
        verification = authentication_manager.verify(request.json["identifier"], request.json["password"])
        print(verification)
        if verification is not None:
            user_id = verification["user_id"]

            # notifying
            requests.post(configuration.notification_url, data={"user_id": user_id, "action": "login"})

            return {"token": verification["token"]}
        else:
            return Response(status=401)
    else:
        return Response(status=400)


@application.route("/logout", methods=["GET"])
def logout():
    if "token" in request.args:
        try:
            object_ = jwt.decode(request.args["token"], configuration.jwt_secret, ["HS256"])

            requests.post(configuration.notification_url, data={"user_id": object_["user_id"], "action": "logout"})

            # TODO: future redirect to login screen
            return Response(status=200)
        except jwt.exceptions.InvalidTokenError as e:
            print(e)
            return Response(status=401)
    else:
        return Response(status=400)


@application.route("/notify", methods=["POST"])
def notify():
    print(request.json)
    if "user_id" in request.json and "action" in request.json:
        print(request.json["user_id"], request.json["action"])

        return Response(status=200)
    else:
        return Response(status=400)


application.run(port=configuration.port, debug=True)
