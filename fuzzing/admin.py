from django.contrib import admin
from .models import FuzzingQueue, FuzzingResult

admin.site.register(FuzzingQueue)
admin.site.register(FuzzingResult)
