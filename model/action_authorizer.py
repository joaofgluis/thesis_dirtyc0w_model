def authorize_action(command, arguments):
    """
    Autoriza ou bloqueia ações específicas mesmo quando o binário é válido.
    Aqui podes definir regras adicionais (ex.: parâmetros proibidos, horários).
    :param command: Binário que vai ser executado
    :param arguments: Lista de argumentos passados ao comando
    :return: True se a ação for permitida, False caso contrário
    """
    # Exemplo: bloquear se tentar usar 'rm -rf /'
    if command == "/bin/rm" and "-rf" in arguments and "/" in arguments:
        return False

    # Neste protótipo, todas as ações passam se não houver regra explícita a bloquear
    return True
