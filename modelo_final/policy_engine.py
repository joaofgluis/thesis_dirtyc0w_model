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