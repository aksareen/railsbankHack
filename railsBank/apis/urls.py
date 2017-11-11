from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^add_user$', views.add_user, name='add_user'),
    url(r'^csrf_token', views.get_csrf_token, name='csrf_token'),
]