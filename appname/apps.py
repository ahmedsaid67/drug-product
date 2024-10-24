from django.apps import AppConfig

class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'appname'

    def ready(self):
        # Import the signals module to ensure signal handlers are connected
        import appname.signals
