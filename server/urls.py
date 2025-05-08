"""
URL configuration for server project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, re_path

from server.views import add_network_stat, change_password, change_username, get_network_stats_by_user, get_user_by_token, login_username, login_email, signup, test_token, add_seen_networks

urlpatterns = [
    path('admin/', admin.site.urls),
    re_path(r'login_username', login_username),
    re_path(r'login_email', login_email),
    re_path(r'signup', signup),
    re_path(r'test_token', test_token),
    re_path(r'add_seen_networks', add_seen_networks),
    re_path(r'user_by_token', get_user_by_token),
    re_path(r'change_password', change_password),
    re_path(r'change_username', change_username),
    re_path(r'add_stats', add_network_stat),
    path('get_stats/<int:user_id>', get_network_stats_by_user, name='get_network_stats_by_user')
]
