from django.contrib import admin
from django.urls import path, include
from rest_framework import routers, permissions
from account_users.views import CustomUserViewSet
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="Humsanity API",
        default_version='v1',
        description="API documentation for Humsanity project",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@humsanity.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

router = routers.DefaultRouter()
router.register(r'users', CustomUserViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]