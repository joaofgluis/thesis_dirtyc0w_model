# command_interceptor.py
#!/usr/bin/env python3
import os
import subprocess
from logger import AuditLogger
from file_protector import FileProtector
from policy_engine import PolicyEngine

class CommandInterceptor:
    """
    Intercepta a execução de comandos privilegiados.
    """
    def __init__(self, policy_engine=None, logger=None, file_protector=None):
        self.policy_engine = policy_engine or PolicyEngine()
        self.logger = logger or AuditLogger()
        self.file_protector = file_protector or FileProtector()

    def intercept(self, command, args):
        user = os.getenv('USER') or 'unknown'
        # Verificação de políticas
        if not self.policy_engine.is_command_allowed(user, command, args):
            self.logger.log(user, command, args, 'DENIED')
            print(f'Comando {command} negado pela política.')
            return 1
        # Verificação de ficheiros protegidos
        for arg in args:
            if self.file_protector.is_protected(arg):
                self.logger.log(user, command, args, 'DENIED')
                print(f'O acesso ao ficheiro {arg} está protegido.')
                return 1
        # Execução do comando
        try:
            resultado = subprocess.run(
                [command] + args,
                check=True,
                capture_output=True,
                text=True
            )
            self.logger.log(user, command, args, 'SUCCESS')
            print(resultado.stdout)
            return 0
        except subprocess.CalledProcessError as e:
            self.logger.log(user, command, args, f'ERROR_{e.returncode}')
            print(e.stderr)
            return e.returncode