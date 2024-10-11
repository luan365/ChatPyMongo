import base64
from database.entities import Message
from pymongo import MongoClient
from database.mongoconnection import connectionstring


class MongoHandler:
    def __init__(self):
        self.client = MongoClient(connectionstring)

    def connect(self, db_name):

        return self.client[db_name]

    def auth(self, email, password) -> bool:
        db = self.connect("chat")
        user = db.users.find_one({"email":email, "password": password})
        if user:
            return True
        else:
            registerUser = input(
                f"Usuário não encontrado. Deseja criar uma conta com o email '{email}'? (s/n): ").lower()

            if registerUser == 's':
                # Chama a função para criar uma nova conta
                add_new_user(email, password)
                return True
            else:
                print("Encerrando o programa.")
                exit()



def update_password(email:str, newpass : str):
    cli = MongoClient(connectionstring)
    db = cli["chat"]
    coll = db.users

    result = coll.update_one(
        {"email": email},  # Encontrar o usuário pelo email
        {"$set": {"password": newpass}}  # Atualizar a senha
    )
    if result.matched_count > 0:
        print("Senha atualizada com sucesso!")
    else:
        print("Usuário não encontrado.")

def delete_user(email :str, senha : str):
    cli = MongoClient(connectionstring)
    db = cli["chat"]
    coll = db.users

    user_data = {
        "email": email,
        "password": senha
    }

    result = coll.delete_one(user_data)

    if result.deleted_count > 0:  # Verifica se algum documento foi excluído
        print("Conta excluída com sucesso!")
    else:
        print("Nenhuma conta encontrada com esse email e senha.")


def is_there_user(email :str):
    cli = MongoClient(connectionstring)
    db = cli["chat"]
    coll = db.users


    existing_user = coll.find_one({"email": email})
    if existing_user:
        return True

def add_new_user(email: str, senha: str):
    cli = MongoClient(connectionstring)
    db = cli["chat"]
    coll = db.users

    # Verifica se o usuário já existe
    existing_user = coll.find_one({"email": email})
    if existing_user:
        return "Usuário já existe!"

    # Adiciona novo usuário
    user_data = {
        "email": email,
        "password": senha  # Aqui você pode adicionar hash na senha se necessário
    }

    result = coll.insert_one(user_data)
    return result.inserted_id  # Retorna o ID do novo usuário


class Operations:
    def __init__(self, email: str, password: str, salt : bytes):

        self.connection_string = connectionstring

    def add_new_message(self, m: Message, salt: bytes):
        cli = MongoClient(self.connection_string)
        db = cli["chat"]
        coll = db.messages
        m.__dict__['salt'] = base64.b64encode(salt).decode()  # Armazenar o salt
        return coll.insert_one(m.__dict__).inserted_id


    def retrieve_messages_from_contact(self, email: str, contact: str):
        cli = MongoClient(self.connection_string)
        db = cli["chat"]
        coll = db.messages

        # Recuperar mensagens entre o usuário e um contato específico
        messages = coll.find({
            "$or": [
                {"email_from": email, "email_to": contact},
                {"email_from": contact, "email_to": email}
            ]
        })

        return list(messages)

    def list_all_contacts(self, email: str):
        cli = MongoClient(self.connection_string)
        db = cli["chat"]
        coll = db.messages

        # Buscar todos os contatos que o usuário já trocou mensagens
        messages = coll.find({
            "$or": [
                {"email_from": email},
                {"email_to": email}
            ]
        })

        # Criar um conjunto único de contatos
        contacts = set()
        for msg in messages:
            if msg["email_from"] != email:
                contacts.add(msg["email_from"])
            if msg["email_to"] != email:
                contacts.add(msg["email_to"])

        return list(contacts)