from django.db import models
from django.contrib.auth.models import User

from random import choice
from datetime import datetime

KEY_LENGTH = 20
SECRET_LENGTH = 40
KEY_OPTION_CHARACTERS = list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')

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
    key = models.CharField(max_length=255, unique=True, default=generate_key)
    secret = models.CharField(max_length=255, default=generate_secret)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    author = models.CharField(max_length=255)
    url = models.URLField(blank=True, null=True,
        help_text='A URL to the application')
    user = models.ForeignKey(User)
    authorized = models.BooleanField()
    public = models.BooleanField()
    num_requests = models.IntegerField(default=0)
    registration_date = models.DateTimeField(default=datetime.now)
    last_request_date = models.DateTimeField(blank=True, null=True)


class RequestToken(models.Model):
    """
    An OAuth request token.

    Stores an OAuth request token for a given consumer application and user.
    """
    key = models.CharField(max_length=80, unique=True, default=generate_key)
    secret = models.CharField(max_length=80, unique=True,
        default=generate_secret)
    callback_url = models.CharField(max_length=255)
    consumer = models.ForeignKey(ConsumerApplication)
    user = models.ForeignKey(User, blank=True, null=True)
    verifier = models.CharField(max_length=255, unique=True, blank=True,
        null=True)
    verified_date = models.DateTimeField(blank=True, null=True)
    creation_date = models.DateTimeField(default=datetime.now)
    authorized = models.BooleanField(default=False)


class AuthorizationCode(models.Model):
    """
    An OAuth authorization code, may be revoked for an access token later.
    """
    consumer = models.ForeignKey(ConsumerApplication)
    user = models.ForeignKey(User)
    code = models.CharField(max_length=80, unique=True, default=generate_key)
    creation_date = models.DateTimeField(default=datetime.now)
    authorized = models.BooleanField(default=True)


class AccessToken(models.Model):
    """
    An OAuth access token.

    Stores an OAuth access token for a given consumer application and user.
    """
    key = models.CharField(max_length=80, unique=True, default=generate_key)
    secret = models.CharField(max_length=80, unique=True,
        default=generate_secret)
    consumer = models.ForeignKey(ConsumerApplication)
    user = models.ForeignKey(User)
    creation_date = models.DateTimeField(default=datetime.now)
    authorized = models.BooleanField()
