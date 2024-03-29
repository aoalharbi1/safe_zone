from django.conf.urls import url
from . import views
                    
urlpatterns = [
    url(r'^$', views.index),
    url(r'^validate$', views.validate),
    url(r'^user_in$', views.user_in),
    url(r'^user_in/message_sent/(?P<user_id>\d+)$', views.send_message),
    url(r'^sign_out$', views.sign_out),
    url(r'^sign_up$', views.registration),
    url(r'^admin$', views.admin),
    url(r'^admin/show_user/(?P<user_id>\d+)$', views.show_user_info),
    url(r'^admin/show_user/(?P<user_id>\d+)/edit$', views.admin_edit_user),
    url(r'^user_in/reports/(?P<report_id>\d+)$', views.show_reports),
    url(r'^edit_info/(?P<user_id>\d+)$', views.edit_info),
    url(r'^user_in/edit_my_profile/(?P<user_id>\d+)$',views.edit_user),
    url(r'^edit_my_profile/(?P<user_id>\d+)$',views.edit_my_profile),
    url(r'^admin/show_user/(?P<user_id>\d+)/report/(?P<report_id>\d+)$', views.admin_show_report),
    url(r'^report/delete$', views.delete_report),
    url(r'^upload$', views.upload_report),
    url(r'^show_report_not_signed_in$', views.show_report_not_signed_in),
    url(r'^', views.default_route)
]