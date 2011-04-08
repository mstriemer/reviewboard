from random import choice
from datetime import datetime, timedelta

from django.db import models
from django.contrib.auth.models import User

KEY_LENGTH = 20
SECRET_LENGTH = 40
KEY_OPTION_CHARACTERS = list('abcdefghijklmnopqrstuvwxyz'
                             'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                             '0123456789')
AUTHORIZATION_DAYS = 30
REFRESH_DAYS = 60

def generate_random_string(size):
    """Generates a key for the given model."""
    return ''.join([choice(KEY_OPTION_CHARACTERS) for c in range(size)])

def generate_key():
    return generate_random_string(KEY_LENGTH)

def generate_secret():
    return generate_random_string(SECRET_LENGTH)


# TODO: ENCRYPT THE SECRET TOKENS!
class ConsumerApplication(models.Model):
    """
    An OAuth consumer application.

    Stores the data that is used by the consumer application to authenticate
    with ReviewBoard along with some information about the application so
    users have some feedback when authorizing access.
    """
    key = models.CharField(max_length=80, unique=True, default=generate_key)
    secret = models.CharField(max_length=80, default=generate_secret)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    author = models.CharField(max_length=255)
    url = models.URLField(blank=True, null=True,
        help_text='A URL to the application')
    user = models.ForeignKey(User)
    redirect_uri = models.URLField()
    authorized = models.BooleanField()
    public = models.BooleanField()
    num_requests = models.IntegerField(default=0)
    registration_date = models.DateTimeField(default=datetime.now)
    last_request_date = models.DateTimeField(blank=True, null=True)

    def get_authorization_code(self):
        """Create an AuthorizationCode for this consumer."""
        authorization_code = AuthorizationCode(consumer=self, user=self.user)
        authorization_code.full_clean()
        authorization_code.save()
        return authorization_code

    def get_access_and_request_token(self):
        """
        Create an access token and a refresh token for this consumer
        and authorization_code.
        """
        access = Token(consumer=self, user=self.user, token_type='access')
        refresh = Token(consumer=self, user=self.user, token_type='refresh')
        access.full_clean()
        refresh.full_clean()
        access.save()
        refresh.save()
        return access, refresh

class AuthorizationCode(models.Model):
    """
    An OAuth authorization code, may be revoked for an access token later.
    """
    consumer = models.ForeignKey(ConsumerApplication)
    user = models.ForeignKey(User)
    code = models.CharField(max_length=80, unique=True, default=generate_key)
    creation_date = models.DateTimeField(default=datetime.now)
    authorized = models.BooleanField(default=True)

    def is_active(self):
        """Check if an authorization code is still valid."""
        return (self.authorized and self.creation_date +
                timedelta(days=AUTHORIZATION_DAYS) > datetime.now())


class Token(models.Model):
    """
    An OAuth access token.

    Stores an OAuth access token for a given consumer application and user.
    """
    consumer = models.ForeignKey(ConsumerApplication)
    user = models.ForeignKey(User)
    token = models.CharField(max_length=80, unique=True, default=generate_key)
    token_type = models.CharField(max_length=30)
    creation_date = models.DateTimeField(default=datetime.now)
    authorized = models.BooleanField(default=True)
