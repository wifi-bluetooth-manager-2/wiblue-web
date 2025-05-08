from django.db import models
from django.core.validators import MinLengthValidator

class Network(models.Model):
    # id = models.BigAutoField(primary_key=True, null=False)
    ssid = models.CharField(max_length=300,validators=[MinLengthValidator(0)])
    bssid = models.CharField(max_length=300,validators=[MinLengthValidator(0)], unique=True)
    security = models.CharField(max_length=300,validators=[MinLengthValidator(0)])
    mode = models.CharField(max_length=300,validators=[MinLengthValidator(0)])



class NetworkStat(models.Model):
    ssid = models.CharField(max_length=255)
    rx_bytes = models.IntegerField(default=0)
    tx_bytes = models.IntegerField(default=0)
    user_id = models.IntegerField(default=1)
    total_bytes_up = models.IntegerField(default=0)
    total_bytes_down = models.IntegerField(default=0)

    def __str__(self):
        return f"NetworkStat for User ID {self.user_id}: {self.ssid}"
