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
