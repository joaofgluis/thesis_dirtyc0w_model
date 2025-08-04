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

            # logger.py
#!/usr/bin/env python3
import logging
    
    class AuditLogger:
    """
    Regista todas as tentativas de execução de comandos privilegiados.
    """
    def __init__(self, logfile='/var/log/tef_audit.log'):
        logging.basicConfig(
            filename=logfile,
            level=logging.INFO,
            format='%(asctime)s %(message)s'
        )
        self.logger = logging.getLogger('TEF')
    def log(self, user, command, args, result):
        """
        Regista no ficheiro de log o utilizador, comando, argumentos e resultado.
        """
        self.logger.info(f'User={user} CMD={command} ARGS={args} RESULT={result}')



        # file_protector.py
#!/usr/bin/env python3
import os

    class FileProtector:
    """
    Define ficheiros com restrições específicas.
    """
    def __init__(self, protected_paths=None):
        # Lista de caminhos absolutos protegidos
        self.protected_paths = protected_paths or ['/opt/confidencial']
    def is_protected(self, path):
        abs_path = os.path.abspath(path)
        return abs_path in self.protected_paths

        # policy_engine.py
#!/usr/bin/env python3

    class PolicyEngine:
    """
    Aplica as políticas definidas no ficheiro de configuração.
    """
    def __init__(self, config_file='/etc/tef_policy.conf'):
        self.policies = self.load_policies(config_file)
    def load_policies(self, config_file):
        policies = {}
        try:
            with open(config_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        cmd, rule = line.split('=')
                        policies[cmd.strip()] = rule.strip()
        except FileNotFoundError:
            pass
        return policies

    def is_command_allowed(self, user, command, args):
        # Se existir uma entrada "comando=deny", nega automaticamente
        if command in self.policies and self.policies[command] == 'deny':
            return False
        return True

        # tef_model.py
#!/usr/bin/env python3
import sys
from logger import AuditLogger
from file_protector import FileProtector
from policy_engine import PolicyEngine
from command_interceptor import CommandInterceptor
    
    class TEFModel:
    """
    Fábrica do modelo TEF: junta todos os componentes e executa o interceptor.
    """
    def __init__(self):
        self.logger = AuditLogger()
        self.file_protector = FileProtector()
        self.policy_engine = PolicyEngine()
        self.interceptor = CommandInterceptor(
            policy_engine=self.policy_engine,
            logger=self.logger,
            file_protector=self.file_protector
        )
    def run(self):
        if len(sys.argv) < 2:
            print('Uso: tef_model.py <comando> [args...]')
            exit(1)
        command = sys.argv[1]
        args = sys.argv[2:]
        exit(self.interceptor.intercept(command, args))

    if __name__ == '__main__':
        TEFModel().run()







