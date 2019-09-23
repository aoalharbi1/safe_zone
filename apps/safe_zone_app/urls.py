from django.conf.urls import url
from . import views
                    
urlpatterns = [
    url(r'^$', views.index),
    url(r'^validate$', views.validate),
    url(r'^user_in$', views.user_in),
    url(r'^sign_out$', views.sign_out),
]