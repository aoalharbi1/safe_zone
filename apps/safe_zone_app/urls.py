from django.conf.urls import url
from . import views
                    
urlpatterns = [
    url(r'^$', views.index),
    url(r'^sign_in$', views.validate),
    url(r'^sign_up$', views.registeration),
]