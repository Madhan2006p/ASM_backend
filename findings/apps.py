from django.apps import AppConfig


class FindingsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'findings'

    def ready(self):
        """
        Called once by Django when the application is fully loaded.
        Faraday pipeline is NOT auto-started here to keep Django
        startup fast and reliable. Run it separately with:
            python manage.py start_faraday_pipeline
        or directly:
            docker compose -f defectdojo_pipeline/docker-compose.yml up -d
        """
        pass
