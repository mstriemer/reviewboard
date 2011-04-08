from django.contrib import admin

from reviewboard.oauth.models import ConsumerApplication, AuthorizationCode, Token

def is_active(obj):
    return obj.is_active()


class ConsumerApplicationAdmin(admin.ModelAdmin):
    list_display = ('name', 'author', 'authorized', 'public', 'num_requests',
                    'registration_date', 'last_request_date')
    search_fields = ['name', 'author']
    ordering = ['name']


class AuthorizationCodeAdmin(admin.ModelAdmin):
    list_display = ('consumer', 'user', 'creation_date', 'authorized', is_active)


class TokenAdmin(admin.ModelAdmin):
    list_display = ('consumer', 'user', 'token_type', 'creation_date', 'authorized', is_active)

admin.site.register(ConsumerApplication, ConsumerApplicationAdmin)
admin.site.register(AuthorizationCode, AuthorizationCodeAdmin)
admin.site.register(Token, TokenAdmin)