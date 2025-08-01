# Lista de binários autorizados a executar com privilégios elevados
SAFE_BINARIES = [
    "/usr/bin/sudo",
    "/usr/bin/passwd"
]

def validate_binary(command):
    """
    Verifica se o binário solicitado está autorizado.
    :param command: Caminho completo do binário
    :return: True se for permitido, False caso contrário
    """
    return command in SAFE_BINARIES
