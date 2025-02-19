from django.contrib import admin
from reference_data.models import Roles
# Register your models here.
class Roleadmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'created_at', 'updated_at')
    search_fields = ('name', 'description')
    list_filter = ('created_at', 'updated_at')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        ('Role', {'fields': ('name', 'description')}),
        ('Audit Info', {'fields': ('created_at', 'updated_at')})
    )
    def save_model(self, request, obj, form, change):
        if not obj.pk:
            obj.created_by = request.user
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)
admin.site.register(Roles,Roleadmin)

