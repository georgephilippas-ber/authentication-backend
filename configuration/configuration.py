from dataclasses import dataclass

from managers.authentication_manager import AuthenticationManager, Agent
from managers.database_provider.mongodb_provider import MongoDBProvider
from model.authentication import hash_password


@dataclass(frozen=True)
class Configuration:
    host: str
    port: int
    local_storage_key: str
    logo_image: str
    login_success_redirect_url: str
    jwt_secret: str
    notification_url: str  # endpoint receiving post requests about user activity
    registration_success_redirect_url: str

    def authentication_url(self):
        return self.host + ":" + str(self.port) + "/" + "/authenticate"

    def logout_url(self):
        return self.host + ":" + str(self.port) + "/logout"

    def registration_url(self):
        return self.host + ":" + str(self.port) + "/register-user"


configuration = Configuration("http://localhost", 0x4000, "access_token",
                              "images/brand/Logo Files/For Web/svg/Black logo - no background.svg",
                              "https://www.google.com/", "jwt_secret", "http://localhost:16384/notify",
                              "http://localhost:" + str(0x4000) + "/")

database_provider = MongoDBProvider("personal")

authentication_manager = AuthenticationManager(database_provider, configuration.jwt_secret)


def initialize_database():
    authentication_manager.drop()


def create_root_user():
    [password_hash, password_salt] = hash_password("root")
    authentication_manager.create(Agent(-1, "root", "root@localhost", password_hash, password_salt))
