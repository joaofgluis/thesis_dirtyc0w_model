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
