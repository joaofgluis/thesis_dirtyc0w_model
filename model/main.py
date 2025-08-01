#!/usr/bin/env python3
import sys
import os

from context_validator import validate_context
from binary_validator import validate_binary
from action_authorizer import authorize_action
from logger import log_event

def main():
    if len(sys.argv) < 2:
        print("[TEF] Erro: Nenhum comando fornecido.")
        sys.exit(1)

    command = sys.argv[1]
    arguments = sys.argv[1:]

    # Camada 1 - Verificação de contexto
    if not validate_context():
        print("[TEF] Bloqueado: execução em contexto não autorizado.")
        log_event(f"[BLOQUEADO] Contexto não autorizado para {command}")
        sys.exit(1)

    # Camada 2 - Validação de binário
    if not validate_binary(command):
        print(f"[TEF] Bloqueado: {command} não está autorizado.")
        log_event(f"[BLOQUEADO] Binário não autorizado: {command}")
        sys.exit(1)

    # Camada 3 - Autorização de ação
    if not authorize_action(command, arguments):
        print(f"[TEF] Bloqueado: ação não autorizada ({' '.join(arguments)})")
        log_event(f"[BLOQUEADO] Ação não autorizada: {arguments}")
        sys.exit(1)

    # Se tudo passou, executa o comando real
    log_event(f"[PERMITIDO] {command} {' '.join(arguments)}")
    os.execvp(command, arguments)

if __name__ == "__main__":
    main()
