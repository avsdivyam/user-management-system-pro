from django.core.management.commands.runserver import Command as RunserverCommand

class Command(RunserverCommand):
    def add_arguments(self, parser):
        super().add_arguments(parser)
        self.default_addr = '127.0.0.1'
        self.default_port = '7575'
