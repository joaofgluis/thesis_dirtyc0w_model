import os

def validate_context():
    """
    Verifica se a execução está a ocorrer num contexto autorizado.
    Exemplo simples: bloquear execução remota via SSH.
    :return: True se o contexto for válido, False caso contrário
    """
    # Bloqueia execuções feitas através de ligação SSH
    if os.getenv("SSH_CONNECTION"):
        return False

    # Poderias adicionar aqui outras regras de contexto:
    # - Terminal físico vs remoto
    # - Sessão interativa vs scripts automáticos
    return True
