from django.conf.urls import url
from . import views
                    
urlpatterns = [
    url(r'^$', views.index),
    url(r'^validate$', views.validate),
    url(r'^user_in$', views.user_in),
    url(r'^user_in/massege_sent/(?P<user_id>\d+)$', views.send_massege),
    url(r'^sign_out$', views.sign_out),
    url(r'^sign_up$', views.registration),
    url(r'^admin$', views.admin),
    url(r'^admin/show_user/(?P<user_id>\d+)$', views.show_user_info),
]