from django.core.management.base import BaseCommand
from reference_data.models import Roles

class Command(BaseCommand):
    help = "Seed initial roles"

    def handle(self, *args, **kwargs):
        roles_data = [
        {'name': 'Admin', 'description': 'Administrator with full access'},
        {'name': 'Coach', 'description': 'Coach with limited access'},
        {'name': 'Student', 'description': 'Student with restricted access'},
        { }
    ]
        for role_data in roles_data:
            role, created = Roles.objects.get_or_create(
            name=role_data['name'],
            defaults={'description': role_data['description']}
        )
            if created:
                print(f"Role '{role.name}' created.")
            else:
                print(f"Role '{role.name}' already exists.")