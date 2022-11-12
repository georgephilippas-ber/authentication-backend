from pymongo import MongoClient
from pymongo.database import Database


class MongoDBProvider:
    client: MongoClient
    database: Database

    def __init__(self, database: str, connection_uri: str = "mongodb://localhost:27017"):
        self.client = MongoClient(connection_uri)
        self.database = self.database(database)

    def database(self, database: str) -> Database:
        return self.client.get_database(database)

    def collections(self):
        return list(map(lambda x: x["name"], list(self.database.list_collections())))

    def collection_exists(self, collection: str):
        return collection in self.collections()
