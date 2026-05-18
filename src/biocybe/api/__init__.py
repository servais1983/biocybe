"""API REST de BioCybe.

Expose les capacités de BioCybe via HTTP/JSON pour intégration SIEM/SOAR :
  - scan à la demande
  - inspection / restauration de la quarantaine
  - santé et métriques Prometheus
  - statut des cellules actives

Voir `app.py` pour les détails. Le point d'entrée principal est
`create_app(config)` qui retourne une `Flask` application prête à
être servie par n'importe quel WSGI (waitress, gunicorn, uwsgi).
"""

from .app import (
    API_TOKEN_ENV,
    APIConfig,
    create_app,
    run_dev,
    run_production,
)

__all__ = ["API_TOKEN_ENV", "APIConfig", "create_app", "run_dev", "run_production"]
