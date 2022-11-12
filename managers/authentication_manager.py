from dataclasses import dataclass, asdict

from pymongo.database import Collection

from managers.database_provider.mongodb_provider import MongoDBProvider

import re
import jwt

from model.authentication import verify_password


@dataclass()
class Agent:
    user_id: int

    username: str
    email: str

    password_hash: bytes
    salt: bytes


def is_email(identifier: str) -> bool:
    regular_expression = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')

    return regular_expression.fullmatch(identifier) is not None


class AuthenticationManager:
    database_provider: MongoDBProvider

    collection_name: str
    collection: Collection

    jwt_secret: str

    def __init__(self, database_provider: MongoDBProvider, jwt_secret: str, collection: str = "AuthenticationManager"):
        self.database_provider = database_provider
        self.collection_name = collection

        self.collection = self.database_provider.database.get_collection(self.collection_name)

        self.jwt_secret = jwt_secret

    def create(self, agent: Agent):
        self.collection.update_one({"user_id": agent.user_id}, {"$set": asdict(agent)}, upsert=True)

    def by_user_id(self, user_id: int) -> Agent | None:
        document = self.collection.find_one({"user_id": user_id}, {"_id": False})

        return Agent(**document) if document is not None else None

    def by_username(self, username: str) -> Agent | None:
        document = self.collection.find_one({"username": username}, {"_id": False})

        return Agent(**document) if document is not None else None

    def by_email(self, email: str) -> Agent | None:
        document = self.collection.find_one({"username": email}, {"_id": False})

        return Agent(**document) if document is not None else None

    def delete(self):
        self.collection.delete_many({})

    def drop(self):
        if self.database_provider.collection_exists(self.collection_name):
            self.collection.drop()

    def all(self):
        return list(map(lambda x: x["user_id"], self.collection.find({})))

    def verify(self, identifier: str, password: str) -> dict | None:
        agent: Agent | None = self.by_email(identifier) if is_email(identifier) else self.by_username(identifier)

        if agent is not None and verify_password(password, agent.password_hash, agent.salt):
            object_ = {"user_id": agent.user_id, "username": agent.username, "email": agent.email}

            return {"token": jwt.encode(object_, self.jwt_secret), "user_id": agent.user_id}
        else:
            return None
