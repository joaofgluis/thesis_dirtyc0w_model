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
