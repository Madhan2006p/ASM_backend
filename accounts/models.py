from django.contrib.auth.models import User as DjangoUser

from authentication.models import Organization as AuthOrganization


class Organization(AuthOrganization):
    class Meta:
        proxy = True
        verbose_name = "Organization"
        verbose_name_plural = "Organizations"


class User(DjangoUser):
    class Meta:
        proxy = True
        verbose_name = "User"
        verbose_name_plural = "Users"
