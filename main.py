import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from database.entities import User, Message
from database.mongoHandler import MongoHandler, Operations, add_new_user, is_there_user, update_password, delete_user


# Função para derivar a chave de criptografia usando PBKDF2
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# Função para gerar um novo salt aleatório
def generate_salt() -> bytes:
    return os.urandom(16)


# Função principal
def main():
    handler = MongoHandler()

    while True:
        print("1 - Criar conta")
        print("2 - Fazer login")
        print("3 - Alterar senha")
        print("4 - Deletar conta")
        print("5 - Sair")
        escolha = input("Escolha: ")

        if escolha == "1":
            criar_conta()
        elif escolha == "2":
            login(handler)
        elif escolha == "3":
            alterar_senha()
        elif escolha == "4":
            deletar_conta()
        elif escolha == "5":
            print("Saindo...")
            break
        else:
            print("Opção inválida, tente novamente.")


# Função para criar uma nova conta
def criar_conta():
    email = input("Email: ")
    senha = input("Senha: ")
    ret = add_new_user(email, senha)
    print(ret if isinstance(ret, str) else "Usuário registrado com sucesso!")


# Função de login
def login(handler: MongoHandler):
    email = input("Email: ")
    senha = input("Senha: ")

    if handler.auth(email, senha):
        print("Usuário logado")
        realizar_operacoes(email, senha)
    else:
        print("Senha inválida" if is_there_user(email) else "Usuário não encontrado")


# Função para realizar operações após o login
def realizar_operacoes(email: str, senha: str):
    password = input("Insira a senha para a criptografia: ")
    salt = generate_salt()
    key = derive_key(password, salt)
    fernet = Fernet(key)
    operations = Operations(email, senha, salt)

    while True:
        print("\n1 - Enviar mensagem")
        print("2 - Checar mensagens (Um contato)")
        print("3 - Listar contatos")
        print("4 - Trocar senha de criptografia")
        print("5 - Sair")
        opcao = input("Opção: ")

        if opcao == "1":
            enviar_mensagem(fernet, operations, email)
        elif opcao == "2":
            checar_mensagens(operations, password)
        elif opcao == "3":
            listar_contatos(operations, email)
        elif opcao == "4":
            trocar_senha()
        elif opcao == "5":
            print("Saindo...")
            break
        else:
            print("Opção inválida, tente novamente.")


# Função para enviar uma mensagem
def enviar_mensagem(fernet: Fernet, operations: Operations, remetente: str):
    destino = input("Para: ")
    conteudo = input("Mensagem: ")
    conteudo_cripto = fernet.encrypt(conteudo.encode()).decode()
    msg = Message(remetente, destino, conteudo_cripto)
    operations.add_new_message(msg, generate_salt())
    print("Mensagem enviada com sucesso!")


# Função para checar mensagens de um contato específico
def checar_mensagens(operations: Operations, password: str):
    contato = input("Contato: ")
    mensagens = operations.retrieve_messages_from_contact(operations.email, contato)

    if mensagens:
        for m in mensagens:
            try:
                salt = base64.b64decode(m['salt'].encode())
                key = derive_key(password, salt)
                fernet = Fernet(key)
                conteudo_descripto = fernet.decrypt(m['content'].encode()).decode()
                print(f"{m['email_from']} -> {m['email_to']}: {conteudo_descripto}")
            except InvalidToken:
                print(f"Erro ao descriptografar mensagem de {m['email_from']}.")
            except Exception as e:
                print(f"Ocorreu um erro: {str(e)}")
    else:
        print("Nenhuma mensagem encontrada.")


# Função para listar todos os contatos com os quais já trocou mensagens
def listar_contatos(operations: Operations, email: str):
    contatos = operations.list_all_contacts(email)
    if contatos:
        print("Contatos com os quais você já trocou mensagens:")
        for contato in contatos:
            print(contato)
    else:
        print("Você ainda não trocou mensagens com ninguém.")


# Função para trocar a senha de criptografia
def trocar_senha():
    nova_senha = input("Insira a nova senha para a criptografia: ")
    print("Senha de criptografia atualizada com sucesso.")


# Função para alterar a senha
def alterar_senha():
    email = input("Email: ")
    nova_senha = input("Nova senha: ")
    update_password(email, nova_senha)
    print("Senha atualizada com sucesso!")


# Função para deletar conta
def deletar_conta():
    email = input("Email: ")
    senha = input("Senha: ")
    delete_user(email, senha)
    print("Conta deletada com sucesso!")


if __name__ == '__main__':
    main()
