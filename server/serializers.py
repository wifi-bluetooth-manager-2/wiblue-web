from rest_framework import serializers
from django.contrib.auth.models import User
from server.models import Network, NetworkStat


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }


class NetworkSerializer(serializers.ModelSerializer):
    class Meta:
        model = Network
        fields = ['ssid', 'bssid', 'security', 'mode']



class NetworkStatSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkStat
        fields = ['ssid', 'rx_bytes', 'tx_bytes', 'total_bytes_up', 'total_bytes_down', 'user_id']
