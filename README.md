# thesis_dirtyc0w_model
Model that prevent privilege escalation


import datetime

LOG_FILE = "/var/log/tef.log"

def log_event(event):
    """
    Regista um evento no ficheiro de log com data/hora.
    :param event: Texto do evento a registar
    """
    with open(LOG_FILE, "a") as log:
        log.write(f"{datetime.datetime.now()} - {event}\n")
