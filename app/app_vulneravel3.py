# =============================================================================
# AVISO: ESTE ARQUIVO CONTÉM VULNERABILIDADES INTENCIONAIS PARA FINS EDUCACIONAIS
# NÃO UTILIZE EM PRODUÇÃO - APENAS PARA ESTUDO DE SEGURANÇA E SAST
# =============================================================================

from flask import Flask, request, jsonify, session
from lxml import etree
import jwt
import datetime
import threading
import json

app = Flask(__name__)

# -----------------------------------------------------------------------
# VULNERABILIDADE 1: Hardcoded Secret (CWE-798)
# JWT secret hardcoded diretamente no código-fonte
# -----------------------------------------------------------------------
JWT_SECRET = "supersecret123"
app.secret_key = "flask-secret-fixo"

# -----------------------------------------------------------------------
# Simulação de banco de dados em memória
# -----------------------------------------------------------------------
users_db = {
    "alice": {
        "id": 1,
        "username": "alice",
        "password": "alice123",          # senha em texto puro
        "email": "alice@empresa.com",
        "cpf": "123.456.789-00",
        "cartao": "4111-1111-1111-1111",
        "cvv": "737",
        "saldo": 1000.0,
        "role": "user",
    },
    "bob": {
        "id": 2,
        "username": "bob",
        "password": "bob456",
        "email": "bob@empresa.com",
        "cpf": "987.654.321-00",
        "cartao": "5500-0000-0000-0004",
        "cvv": "123",
        "saldo": 500.0,
        "role": "user",
    },
}

# Saldo compartilhado usado na race condition
shared_account = {"saldo": 100.0}


# =============================================================================
# ENDPOINT 1 — LDAP Injection  (CWE-90 / OWASP A03:2021)
# =============================================================================
@app.route("/search", methods=["GET"])
def search():
    """
    VULNERABILIDADE: LDAP Injection
    O parâmetro 'username' é inserido diretamente no filtro LDAP sem
    sanitização ou escape, permitindo que um atacante manipule a query.

    Exemplo malicioso: /search?username=*)(uid=*)(%00
    """
    username = request.args.get("username", "")

    # Query LDAP construída com concatenação direta de input do usuário
    ldap_filter = f"(&(objectClass=user)(uid={username}))"

    # Simulação da execução da query (em produção seria ldap3 ou python-ldap)
    resultado_simulado = {
        "filtro_executado": ldap_filter,
        "usuarios_encontrados": [u for u in users_db if username in u],
    }

    return jsonify(resultado_simulado)


# =============================================================================
# ENDPOINT 2 — XML External Entity (XXE)  (CWE-611 / OWASP A05:2021)
# =============================================================================
@app.route("/parse", methods=["POST"])
def parse_xml():
    """
    VULNERABILIDADE: XXE (XML External Entity Injection)
    O parser lxml é configurado com resolve_entities=True (padrão inseguro),
    permitindo que entidades externas sejam processadas e exfiltrem arquivos
    locais ou causem SSRF.

    Payload malicioso:
    <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <root><data>&xxe;</data></root>
    """
    xml_data = request.data

    # Parser sem proteção contra XXE — resolve_entities não desativado
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    try:
        tree = etree.fromstring(xml_data, parser)
        resultado = {campo.tag: campo.text for campo in tree}
        return jsonify({"parsed": resultado})
    except Exception as e:
        return jsonify({"erro": str(e)}), 400


# =============================================================================
# ENDPOINT 3 — Race Condition  (CWE-362 / OWASP A04:2021)
# =============================================================================
@app.route("/transfer", methods=["POST"])
def transfer():
    """
    VULNERABILIDADE: Race Condition (TOCTOU — Time of Check to Time of Use)
    A verificação do saldo e o débito são operações separadas sem lock,
    permitindo que múltiplas requisições simultâneas passem na verificação
    antes que qualquer uma delas efetue o débito.

    Exploração: disparar N requisições simultâneas com valor <= saldo atual
    para sacar mais do que o saldo disponível.
    """
    data = request.get_json()
    valor = float(data.get("valor", 0))

    # TOCTOU: verifica saldo AQUI...
    if shared_account["saldo"] >= valor:
        # ... simula latência de processamento bancário
        import time; time.sleep(0.1)

        # ... e debita AQUI — sem lock entre as duas operações
        shared_account["saldo"] -= valor
        return jsonify({
            "status": "transferencia_realizada",
            "valor": valor,
            "saldo_restante": shared_account["saldo"],
        })

    return jsonify({"erro": "saldo_insuficiente"}), 400


# =============================================================================
# ENDPOINT 4 — Sensitive Data Exposure  (CWE-200 / OWASP A02:2021)
# =============================================================================
@app.route("/profile", methods=["GET"])
def profile():
    """
    VULNERABILIDADE: Sensitive Data Exposure
    Retorna campos altamente sensíveis (CPF, número de cartão, CVV, senha)
    diretamente na resposta da API sem qualquer mascaramento ou filtragem.
    """
    username = request.args.get("username", "alice")
    usuario = users_db.get(username, {})

    # Retorna o dicionário completo — incluindo senha, CVV, cartão e CPF
    return jsonify(usuario)


# =============================================================================
# ENDPOINT 5 — Broken Authentication  (CWE-287 / OWASP A07:2021)
# =============================================================================
@app.route("/admin", methods=["GET"])
def admin():
    """
    VULNERABILIDADE: Broken Authentication
    Verifica autenticação apenas por parâmetro de query (?admin=true),
    sem validar sessão, token JWT ou qualquer credencial real.
    Qualquer usuário pode acessar passando admin=true na URL.
    """
    # Controle de acesso baseado em parâmetro manipulável pelo cliente
    is_admin = request.args.get("admin", "false")

    if is_admin == "true":
        dados_sensiveis = {
            "painel": "admin",
            "usuarios": list(users_db.values()),
            "chave_jwt": JWT_SECRET,        # expõe o segredo do JWT
            "secret_key": app.secret_key,
        }
        return jsonify(dados_sensiveis)

    return jsonify({"erro": "acesso_negado"}), 403


# =============================================================================
# ENDPOINT 6 — Mass Assignment  (CWE-915 / OWASP A04:2021)
# =============================================================================
@app.route("/update", methods=["POST"])
def update_profile():
    """
    VULNERABILIDADE: Mass Assignment
    Todos os campos do JSON recebido são aplicados diretamente ao modelo
    do usuário sem whitelist. Um atacante pode elevar seu próprio papel
    enviando {"role": "admin"} ou alterar o saldo com {"saldo": 999999}.
    """
    data = request.get_json()
    username = data.get("username", "alice")

    if username in users_db:
        # Aplica TODOS os campos recebidos sem validação de campos permitidos
        users_db[username].update(data)
        return jsonify({
            "status": "perfil_atualizado",
            "usuario": users_db[username],
        })

    return jsonify({"erro": "usuario_nao_encontrado"}), 404


# =============================================================================
# ENDPOINT EXTRA — Geração de token JWT com segredo hardcoded
# =============================================================================
@app.route("/login", methods=["POST"])
def login():
    """
    Gera um JWT assinado com o segredo hardcoded JWT_SECRET.
    Qualquer pessoa que conheça (ou adivinhe) o segredo pode forjar tokens.
    """
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    usuario = users_db.get(username)
    # Comparação de senha em texto puro (sem hashing)
    if usuario and usuario["password"] == password:
        payload = {
            "sub": username,
            "role": usuario["role"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        return jsonify({"token": token})

    return jsonify({"erro": "credenciais_invalidas"}), 401


# =============================================================================
# VULNERABILIDADE 8: Debug mode + host 0.0.0.0  (CWE-94 / OWASP A05:2021)
# Expõe o Werkzeug debugger interativo na rede — permite RCE via console
# =============================================================================
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
